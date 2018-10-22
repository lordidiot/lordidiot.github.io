---
layout: post
title: "Hitcon CTF 2018 - Abyss I (pwn)"
description: "Still a bell, not yet a delver"
date: 2018-10-22
tags: [ctf, pwn, kernel]
comments: true
---

> The Edge of the Abyss
>
> nc 35.200.23.198 31733 (Solves: 42, 230 pts)
>
> [user.elf][binary] [libc.so.6][libc] [kernel.bin][kernel] [+exploit1.py][exploit1]

This challenge was presented as a 3-part challenge. We were expected to pwn user space, kernel space, and finally pwn the KVM hypervisor. I was only able to get the user space part of the challenge (and not without any struggle). However, I think this was an interesting challenge and a good opportunity to learn a bit more the "Abyss" beyond the "Edge of the Abyss" of computers.

The challenge presented us with a [hypervisor.elf][hypervisor] file, a kernel.bin file, a user.elf file and some other dependency files. In this writeup, I will be focusing on pwning the user.elf binary which would be a user space exploit. The hypervisor in this challenge required a 18.04 libc that I was not able to preload in my normal OS, while my 18.10 docker did not have the `/dev/kvm` file required for the hypervisor, thus I proceeded to exploit user.elf without running it in the custom kernel. This would mean that I would not be able to identify special cases in the custom kernel, however, I found some workarounds for this.

## Breaking the "Stack"
This challenge implemented a program parses through a user's input and reads them as opcodes for a stack machine. It also implements a separate map of memory where we can store values and retrieve them later using their index as identification. This is a different architecture from what we are used to, as it does not have any registers. Seeing that this stack machine is similar to something like a brainfuck interpreter, my experience led me to search around for any flawed bounds checking that might allow us to modify/leak data beyond the safe stack and memory region. However, as the bounds checking were done using unsigned numbers, I did not find any misimplemented bounds checking. Upon further checking of the opcodes we can use, I realised that there was no bounds checking for the swap operation, and it just assumes that our stack would contain >2 values. Since the `stack_top`(originally called machine) variable in the bss is placed right before our "stack" in the bss, if we only had 1 value in the stack, the swap operation would swap the stack_top with our first stack value. With this, we can set our stack_top to be -1, which would not equal to 0, thus we can traverse backwards in the bss using `pop` opcodes, outside of the stack. We thus successfully break out of the stack and can now leak and modify values in the bss (like GOT entries).

## No-leak overwrites?
The next issue I faced was that although we can now leak any values, we cannot use the normal push opcodes to overwrite the entries in the GOT as we do not have any interactive abilities with the program. The opcodes we send in are "one-shot", they are all ran and the program exits afterwards. Thus, even with a libc or PIE leak, we would not be able to interactively provide the new addresses to overwrite with. My first idea was that perhaps ASLR was not enabled. Now while 99% of CTF challenges would enabled ASLR as it is default on many systems, our challenge is running on a custom kernel, and I think that the kernel is what handles ASLR protections. Since I couldn't run the kernel locally in the hypervisor, and I was NOT going to reverse the kernel just to check this, I tested my hypothesis on the server. To do this, I sent in a string of opcodes that would break the stack and allow us to leak many values in the bss using the `writed` opcode which prints values to the screen. Unfortunately, the addresses kept changing and thus ASLR and PIE were working as intended. Thus, we must be more creative with our usage of the instructions provided. My solution was to store the higher and lower DWORD of PLT address in the GOT (this would be from functions that haven't yet been resolved), using the `store` opcode. This technique destroys the DWORD right below the address we are extracting, and so I extracted the `write@PLT` address which would break the `strlen` GOT entry, but strlen wasn't called later in the program so this wasn't an issue. Now with this values stored, I could use the `add` or `minus` opcode to modify the lower DWORD of the address we stored to another offset from the binary base, allowing us to write different functions. Since the higher DWORD wouldn't change, it made things easier. Thus I stored a few DWORDS for `printf`, `scanf` and `main`.

```
						33 34	puts
						31 32	write
						29 30	strlen
						27 28	__stack_chk_fail
						25 26	setbuf
						23 24	printf
						21 22	scanf
						19 20	__ctype_b_loc
```
* functions on the GOT and the order at which their DWORDS will be pop'd off

## zero_gadget
It's almost reflex at this point when I control RIP in a CTF challenge to try running a libc one_gadget. My mindset wasn't any different for this challenge and thus I instintively crafted a one_gadget using libc addresses in the GOT, trying to pop a shell. This might not be such a bad idea until you realise that this challenge is NOT running on our usual linux system and linux kernel, and thus we may not even have the program `/bin/sh` to execute! This turned out to be true and none of the one_gadgets worked.

## ret_to_main
Earlier I mentioned that I stored the low DWORDS for `printf`, `scanf` and `main`, and went on a tangent about one_gadgets. Anyways, you might be able to guess what we can do with these functions. With main, we can overwrite a function that we haven't called like `write`, when we use the write opcode it will send us back to main and we can send a new set of opcodes again to process! With this, we can now break our attack up into multiple stages, allowing us to perform leaks or other preparation necessary, returning to main each time by ending with the write opcode. Now printf and scanf are very powerful in this case, as we have one function that is called with our user-inputted string as the first argument, `strlen`. This means that if we overwrite the GOT entry of strlen with printf or scanf, we can perform a format string attack :D. Since the question's hint was `NX?`, I assumed that NX protections were not implemented in the kernel, thus we could write shellcode on stack and jump to it. Therefore, my execution steps made use of `printf(",%8$p")` in order to leak a stack address, and the comma at the start immediately sends execution back to main in order to prevent the program from continuing to process the other characters in the format string as opcodes, which may mess up our execution since our stack_top is in the GOT. Afterwards I made use of the opcodes to write the address of scanf into strlen. Now my format string attack was `scanf("%8$s")` which allows us to write infinitely into a stack address, allowing us to have a stack-based buffer overflow. Exploitation from here was easy, as it was a standard buffer overflow into return to shellcode on stack attack. This time, I learnt my lesson and didn't write a execve shellcode, but rather a open-read-write(ORW) shellcode to read the flag.

`hitcon{Go_ahead,_traveler,_and_get_ready_for_deeper_fear.}`

## Delving deeper into the Abyss
After solving the first challenge, I was optimistic to make my attempt at my first kernel exploit. However, I had a lot of difficulty even reversing the kernel binary, let alone trying to exploit the execution. I managed to find a [github repo][boilerplate] by david942j(the challenge author), which contained a lot of the boiler plate code implemented in the kernel. It was an interesting activity to rename all the functions and slowly uncover some easier parts of the kernel logic. It's only after doing this that I noticed many things I should have noticed to help me with this challenge, for example, the open syscall actually had a whitelist, that only allowed files like "flag", "./user.elf" and some other files to be read. Luckily this did not affect me or I would have gone insane trying to figure out what was wrong with my shellcode. It was also quite interesting to see the implementation of syscalls using the `syscall_handler` and the syscall jump table in memory. Unfortunatly, I didn't find anything that stood out to me as my understanding of kernel exploitiation was quite limited. I hope to learn more and maybe complete the next 2 parts of this challenge, then maybe I can consider myself a "delver" :D. 

PS: If anybody wants to be like Reg and help me out in this abyss that is the land of kernels and hypervisors, do HMU.


[binary]:{{site.baseurl}}/ctf/2018-10-22-hitcon-ctf-2018---abyss/user.elf
[libc]:{{site.baseurl}}/ctf/2018-10-22-hitcon-ctf-2018---abyss/libc.so.6
[kernel]:{{site.baseurl}}/ctf/2018-10-22-hitcon-ctf-2018---abyss/kernel.bin
[hypervisor]:{{site.baseurl}}/ctf/2018-10-22-hitcon-ctf-2018---abyss/hypervisor.elf
[exploit1]:{{site.baseurl}}/ctf/2018-10-22-hitcon-ctf-2018---abyss/exploit1.py
[boilerplate]:https://github.com/david942j/kvm-kernel-example/tree/master/kernel