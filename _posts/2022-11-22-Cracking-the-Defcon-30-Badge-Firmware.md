---
title: "Cracking the DEFCON 30 Badge Firmware"
date: 2022-11-22
description: "Flash extraction and reversing of the DC30 badge firmware."
tag: ["firmware rev","chip extraction","badge"]
categories: ["CTF","Embedded"]
---
<img src="/assets/posts/2022-11-22/Screenshot_7.png" /> 
Extracting and reversing the firmware of the DC30 badge to beat the badge challenge!
<!--more-->

# Table of contents 
1. [Backstory](#backstory) 
2. [Firmware Extraction](#extraction) 
3. [Analysis and Finding Check](#analysis) 
4. [Mapping and Decoding](#mapping) 

<a name="backstory"></a> 
### Backstory and Objective  
Once upon a time I was very excited to fly to Las Vegas and attend <a href="https://defcon.org/html/defcon-30/dc-30-index.html">DEFCON 30</a> the annual go-to security conference. This was going to be my first conference and I had purchased pre-registration tickets, which was a new system that DEFCON was using to allow attendees to guarantee a badge and semi-skip LINECON. However, because of a personal emergency that appeared last minute, I was unable to attend and I gifted my pre-registration to my good friend and mentor <a href="https://ctftime.org/user/3509">playoff-rondo</a>. Later on when I was catching up with him he gave me his badge. DEFCON badges usually have some sort of challenge on them and this year's badge was some sort of piano keyboard. <a href="https://github.com/Kybr-git/DC30-Badge-Challenge-Writeup/blob/main/README.md">This is the writeup made by the attendee that solved the badge challenge and won a black badge</a>, as you can see it is meant to be solved in part by interacting with other attendees who have a different variant of the badge. This is obviously not possible for me, so my goal was to reverse engineer the badge and find what key combo needs to be pressed in order to win the first part of the challenge. 
 
<a name="extraction"></a> 
### Part 1: Extracting Firmware from SPI Flash 
I began by using a magnifying glass, pen and paper to identify all the visible chips on the PCB.

<img src="/assets/posts/2022-11-22/Screenshot_1.png" /> 

The two important chips to note are the <a href="https://www.winbond.com/hq/product/code-storage-flash-memory/serial-nor-flash/?__locale=en&partNo=W25Q16JV">Winbond W25Q16JV</a> (flash chip) and the <a href="https://thepihut.com/products/raspberry-pi-rp2040-microcontroller">RP2 B2</a> (microcontroller). The flash memory chip will be used to grab the firmware and will be the target chip to physically extract. The microcontroller will be used to determine the architecture, conventions and other information that will be useful when analyzing the firmware. 
 
There are tools available to extract firmware from a surface-mounted chip without having to actually remove the component, however I will be using a <a href="https://www.aliexpress.us/item/2251832631316605.html?spm=a2g0o.ppclist.product.2.42fduQgFuQgFn0&pdp_npi=2%40dis%21USD%21US%20%248.25%21%248.00%21%21%21%21%21%402101c84a16691420847026788ea9a4%2112000018677635870%21btf&_t=pvid%3A91be51b8-068b-46f5-ad65-2474e20aa1d4&afTraceInfo=32817631357__pc__pcBridgePPC__xxxxxx__1669142084&gatewayAdapt=glo2usa&_randl_shipto=US">TL866II+ universal programmer</a>, so I will have to remove the chip from the PCB, feed the chip to the device using the appropriate adapter and connect the programmer to my VM for extraction. A heat gun would be ideal for removing a small surface mounted chip like this without damaging the PCB, however I do not have access to such equipment, so I use a soldering iron and tweezers. I heat up each joint of the chip with the iron and lift the leg up with tweezers and a magnifying glass. After I have detached the chip from the board, I go around with the iron again and a desoldering pump in an attempt to clean up as much excess solder as possible from each leg. Then I lock the flash chip in the corresponding adapter and insert it into the TL866II+. 

<img src="/assets/posts/2022-11-22/Screenshot_2.png" /> 

Unfortunately, the whole ordeal was pretty messy and resulted in a bit of copper from the PCB being destroyed (as is natural for my first chip-off extraction). 

<img src="/assets/posts/2022-11-22/Screenshot_3.png" /> 

In my ubuntu machine I use <a href="https://gitlab.com/DavidGriffith/minipro/">the minipro program</a> to interact with the chip programmer. The following command writes the firmware to a file.  
```bash
minipro -p "W25Q16JV@SOIC8" -r flash.bin 
``` 
 
I can verify that this is the firmware by running `strings` and examining the output. 

<img src="/assets/posts/2022-11-22/Screenshot_4.png" /> 
 
<a name="analysis"></a> 
### Part 2: Analyzing Firmware and Finding the Comparison Function 
The MCU is a rpi2040 which makes use of the <a href="https://en.wikipedia.org/wiki/Execute_in_place">"execute in place"</a> feature. This is a feature that improves performance by enabling execution directly in flash storage rather than execution in the MCU's limited memory area. It is important that we keep this in mind before starting to analyze the firmware. Firmware has no entry point and instead has a defined address at which program execution begins. We can find this base address by viewing the <a href="https://datasheets.raspberrypi.com/rp2040/rp2040-datasheet.pdf">rpi2040 datasheet</a> and navigating to the "Address Map" page from the table of contents. The base address will be the XIP address (execute in place). We need to specify this address as the base address in whatever we use to analyze the firmware to load the correct segment. 

<img src="/assets/posts/2022-11-22/Screenshot_5.png" /> 
 
Using Binaryninja I can specify the base address when creating a new project. Binja automatically detects the thumb2 ARM architecture. 

<img src="/assets/posts/2022-11-22/Screenshot_6.png" /> 
 
I start to try and identify useful symbols and organize the code by searching through strings and going to their code references. 

<img src="/assets/posts/2022-11-22/Screenshot_7.png" /> 
 
Some areas have been incorrectly loaded as symbols so I undefine them. 

<img src="/assets/posts/2022-11-22/Screenshot_8.png" /> 

<img src="/assets/posts/2022-11-22/Screenshot_9.png" /> 
 
I also rename symbols that have obvious functions for clarity. 

<img src="/assets/posts/2022-11-22/Screenshot_10.png" /> 
 
Identifying and following the code reference of the interesting string, "YOU DID IT!" leads to what seems to be the function that is called when a correct key combination is entered. 

<img src="/assets/posts/2022-11-22/Screenshot_11.png" /> 
 
The only code reference leads to the following function. The first thing I noted when initially examining it was the comparison inside the loop to 0x2d. This conditional is equal to `if(r3_1 == 0x2d(which is 46))` since the if-statement ends in a break. Examining the note count on my own badge and noting the number of badges with different variations, we know the total number of piano keys that make-up the passing combo is 46, since all badge's music sheets will be used. 

<img src="/assets/posts/2022-11-22/Screenshot_12.png" /> 
 
The decompilation process complicated this loop a bit, so for sanity's sake lets simplify it a bit in our heads. The while loop iterates over the length of the correct combo, once it reaches 46 (the length of the combo) it succeeds. The second if-statement is most important, it compares every key (it gets the key by referencing the location of the key presses in memory with the offset of the current index) with the given character at **string[index]** if it is not equal, it breaks ending the while loop early and never reaching the success block, else it increments combo_length. So the string in the second conditional is what we need to pay attention too. 
 
`C@><>@C@><>@C@CE@EC@><C@><>@C@><>@>@C@CE@EGDB@` 
 
Since each key press is being compared with this string, it is safe to assume that each character in this string is mapped to a physical key on the badge. We should find another function which identifies this mapping. This would likely be the keypress code blobs directly. 
 
Some things to note before continuing: 
- User key buffer stored @ 0x2000xxxx (keypresses). 
- The checkwin function will likely be called every time a key is pressed, to check if the newly modified buffer is a win. 
 
<a name="mapping"></a> 
### Part 3: Finding the Mapping and Decoding the Key Combo 
checkwin has a lot of code references. Each call is likely in a blob for a key press. I'll pin the references window and tag them all to keep everything organized and visible on the pane. 

<img src="/assets/posts/2022-11-22/Screenshot_13.png" /> 

<img src="/assets/posts/2022-11-22/Screenshot_14.png" /> 
 
Examining the very first reference we can take note that a pointer is being passed as the argument. The value at this pointer is being assigned above. For this instance that value is 0x3c, whose ascii representation is "<". 

<img src="/assets/posts/2022-11-22/Screenshot_15.png" /> 
 
Each blob that assigns a mapping is sequential in the code block, so I can safely assume that these are the keyboard mappings assigned in the order as they appear on the physical keyboard. 

<img src="/assets/posts/2022-11-22/Screenshot_16.png" /> 
 
Proceeding to the next checkwin call will reveal the mapping for the C# key (the little black key) which comes next. 

<img src="/assets/posts/2022-11-22/Screenshot_17.png" /> 

<img src="/assets/posts/2022-11-22/Screenshot_18.png" /> 
 
Proceeding through every checkwin call will reveal the character mappings for the entire keyboard. 

<img src="/assets/posts/2022-11-22/Screenshot_19.png" /> 
 
# Hurray! 
 
With these mappings we can decipher the string compared in the checkwin function to the equivalent keys on the keyboard. 
```python
key_map = {"<":"C","=":"C#",">":"D","?":"D#","@":"E","A":"F", 
"B":"F#","C":"G","D":"G#","E":"A","F":"A#","G":"B"} 
key_combo = "" 
for c in "C@><>@C@><>@C@CE@EC@><C@><>@C@><>@>@C@CE@EGDB@": 
  key_combo += key_map.get(c)+" " 
 
print(key_combo) 
``` 
 
The following is the correct key-combination/tune we need to play on the badge keyboard in order to pass the first challenge. 
`G E D C D E G E D C D E G E G A E A G E D C G E D C D E G E D C D E D E G E G A E A B G# F# E` 
 
 
# Sources 
- <a href="https://www.winbond.com/hq/support/documentation/levelOne.jsp?__locale=en&DocNo=DA00-W25Q16JV.1">https://www.winbond.com/hq/support/documentation/levelOne.jsp?__locale=en&DocNo=DA00-W25Q16JV.1</a> 
- <a href="https://datasheets.raspberrypi.com/rp2040/rp2040-datasheet.pdf">https://datasheets.raspberrypi.com/rp2040/rp2040-datasheet.pdf</a> 
