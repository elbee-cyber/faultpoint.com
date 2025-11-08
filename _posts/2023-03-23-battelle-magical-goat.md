---
title: "Feed the Magical Goat (Battelle)"
date: 2023-03-23
description: "Reversing challenge from Battelle showcasing angr's file simulation feature."
tag: ["angr","reversing","CTF","file-sim"]
categories: ["CTF"]
image: /assets/posts/2023-03-23/Screenshot_8.png
---

Reversing challenge from Battelle showcasing angr's file simulation feature!
<!--more-->

# Table of contents
1. [Reversing](#reversing)
2. [Angr Solve](#angr)

<a name="reversing"></a>
### Part 1: Reversing

The following is a writeup for a reverse engineering challenge made by Battelle as one of their cyber career challenges. This challenge explores the use of [angr](https://angr.io) and its ability to emulate file systems for the use of symbolic data. If you are unfamiliar with Angr and the concept of symbolic execution, I made a [YouTube](https://youtu.be/QkVzjn3z0iw) video exploring and explaining this which I (obviously) highly recommend you watch.

A zip file containing a 32-bit, unstripped ELF is provided as part of the challenge. Running the binary outputs a bunch of text and then ends with the binary deleting itself.

![](/assets/posts/2023-03-23/Screenshot_2.png)

Starting a Binja project and looking through the strings reveals the following:
- File operations
- A filename
- A flag format string (Character by character, flag is likely calculated within the binary)

![](/assets/posts/2023-03-23/Screenshot_3.png)

![](/assets/posts/2023-03-23/Screenshot_4.png)

![](/assets/posts/2023-03-23/Screenshot_5.png)

Viewing `main`, a function is called which interacts with what is likely the expected file called `give_offering`.

![](/assets/posts/2023-03-23/Screenshot_6.png)

The function first opens `chow.down` and assigns the stream to `eax`. The following conditional checks if the operation was not successful via checking the file descriptor in `eax`. If it wasn't, the program closes the file descriptor, unlinks the binary (deletes it), prints the outro and calls `exit`. From here on I will refer to this blob as the fail block. Assuming this conditional was false, the file is allocated onto the heap at `eax_2`. The next conditional checks if `eax_2` is `0x40`; if true a hint is printed, both the elf and `chow.down` are deleted and the chunk is freed, followed by a fail block. The next conditional returns the pointer to the file contents and is the path I have to follow in order to continue program execution. It checks if more than `0xf` bytes were read.

![](/assets/posts/2023-03-23/Screenshot_7.png)

Returning to `main`, multiple conditions are checked against various offsets of the file content. If code execution continues without a conditional being true, the flag is printed using these file content offsets, of which I assume were operated on by the functions in the conditions.

![](/assets/posts/2023-03-23/Screenshot_8.png)

Looking at just one of the functions reveals that it is quite complicated.

![](/assets/posts/2023-03-23/Screenshot_9.png)

Manually reversing these functions would be significantly detrimental to my mental health, so instead I'll use symbolic execution to find an execution path that leads to the flag print and what the file contents need to be in order for this path to execute. Angr is a symbolic execution engine for Python that utilizes Microsoft’s SMT solver Z3 and a simulation manager to manage execution states. It is also capable of file system emulation. Using this feature will be simpler than alternative methods of symbol placement, such as directly injecting into memory.

<a name="angr"></a>
### Part 2: I'm Angry FS

The following is my solve script:

```python
import angr,claripy,sys

p = angr.Project("./billygoat")
s = p.factory.blank_state(addr=0x8048f46)

symbol = claripy.BVS('file',8*0xf)
f = angr.storage.SimFile("chow.down", content=symbol)
s.fs.insert("chow.down",f)

def win(state): # Check stdout for "flag{" and print flag
        out = str(state.posix.dumps(sys.stdout.fileno()))
        if "flag{" in out:
                print("Flag: flag"+out.split("flag")[1][:-3])
        return "flag{" in out

simgr = p.factory.simulation_manager(s)
simgr.explore(find=win, avoid=0x80490ce)

print(b"Input: "+simgr.found[0].posix.closed_fds[0][1].concretize())
```

Let's step through it to understand it better.

The first few lines create the Angr project, create the initial state which starts in `give_offering` (`0x8048f46`) and creates a symbol whose size is based on the constraint within that function.

```python
p = angr.Project("./billygoat")
s = p.factory.blank_state(addr=0x8048f46)

symbol = claripy.BVS('file',8*0xf)
```

Next a `SimFile` object is created with the name `chow.down` and whose content is the symbolic data. It is then inserted into the simulated file system.

```python
f = angr.storage.SimFile("chow.down", content=symbol)
s.fs.insert("chow.down",f)
```

Moving on, a function to check for a valid state is created. It checks for the substring `flag{` in the stdout and prints it. Then the simulation manager is created and explored with `find` set to this function and `avoid` set to the fail block.

```python
def win(state): # Check stdout for "flag{" and print flag
        out = str(state.posix.dumps(sys.stdout.fileno()))
        if "flag{" in out:
                print("Flag: flag"+out.split("flag")[1][:-3])
        return "flag{" in out

simgr = p.factory.simulation_manager(s)
simgr.explore(find=win, avoid=0x80490ce)
```

The last line is interesting and I initially had to get help with this as Angr has some issues with managing file descriptors. Essentially its purpose is to print out the symbolic content of the file that led to the success block.

```python
print(b"Input: "+simgr.found[0].posix.closed_fds[0][1].concretize())
```

Looking at the source of [Angr's posix plugin](https://github.com/angr/angr/blob/master/angr/state_plugins/posix.py) can help clarify this line a bit better. A deep copy of the `SimState` is created and the `closed_fds` copy is a list of the super object's `closed_fds`, which is also a list. This line accesses the right file descriptor and patches the input together using `concretize`.

![](/assets/posts/2023-03-23/Screenshot_11.png)

With that, the challenge is solved.

![](/assets/posts/2023-03-23/Screenshot_12.png)