---
layout: post
title: "CTFZone Quals 2018 - Buggy PWN (pwn)"
description: ""
date: 2018-07-23
tags: [ctf, pwn]
comments: true
---

> A disgruntled employee has recently left our team. Unfortunately, he took a flag with him. We've discovered that there is strange buggy service currently in development on his server. Maybe you can get the flag from there.
nc pwn-02.v7frkwrfyhsjtbpfcppnu.ctfz.one 1337
(Solves: 31, 138pts)

> [buggy_pwn.py][buggypwn] [+exploit.py][exploit] [+disassembler.py][disassembler]

This was a very interesting pwn challenge for me. I've never dared to try any challenge in the past with custom-ish architecture and I'm really happy I managed to solve this.

The challenge service runs on a custom architecture implemented in python that is quite similar to x86. However, the major difference is that memory addressing is not linear, instead the memory area is a plane, with every memory location being an imaginary number (real, imaginary) or (x, y). After quickly looking at the `run()` and `processCommand()` functions, it was quite obvious that I would have to somehow disassemble the large chunk of instructions in `self.memory[0]`.

{% highlight python %}
def __initializeprogrammemory(self):
		self.memory=[
			#CARM.MemRange(0x40000,0x40000,30,10,"0\x10\x49\x01 \x01\x00"+" \x01"*600),   #Executable code
			#self,startx,starty,lenx,leny,contents,restricted=True
			CARM.MemRange(0x60000,0x60000,300,1,
			"\x45\x00\x06\x00\x00\x00\x06\x06\x00\x00"+
			"\x00\x00"+
			"\x31\x05\x40\x40\x00\x00\x06\x06\x00\x00"+
			"\x31\x03\x04\x00\x00\x00\x00\x00\x00\x00"+
			"\x31\x06\x01\x00\x00\x00\x00\x00\x00\x00"+
			"\x49\x03"+
					...
{% endhighlight %}
There really isn't much to say about reversing the opcodes they provided. You'll just have to read through the source code and implement the disassembly for each opcode.

![code graph][graph]

Here is a simple code graph I created from the disassembly

After disassembling you'll have a good enough idea of how the code works. The way to get the flag would be to run the `__command_syscall` instruction(when eax = 'f','l' and ebx = 'a','g'). The vulnerability occurs when the program asks for a name from the user. This name will overflow into the `saved eip` in the stack and allow for code redirection. However, only printable characters can be used for your name and thus you cannot overwrite the entire address, a partial overwrite to return to the ".bss" section (0x60040, 0x60040) will work.

This ".bss" section is only writable using printable characters too and thus the shellcode we create must only use printable opcodes and data.

There were two main issues faced when creating the shellcode:
1. Small "real" area to write shellcode.
	- The ".bss" section we return to only has a range of 0x0 - 0x10 in the real axis for us to add shellcode. One way to bypass this would be to jump from 0i to 1i and continue running our shellcode, however I didn't manage to find anyway to run shellcode without it being one contiguous chunk. The solution I found was to use the `__command_rotip` opcode which allows us to traverse in the imaginary axis instead, which has a larger range of 0x0 - 0x40, enough for our shellcode.
2. Only printable characters.
	- Running instructions was not the main issue in this case, since all the opcodes had values that were within the printable ascii range. However, the amplifiers or arguments required for these opcodes occasionally were not in the range. For example, when using `__command_mov_data` to try to get the ascii value of 'f' into `eax`, you would require the DWORD value '\x66\x00\x00\x00' in memory. However, '\x00' is not printable and thus this would not work. The solution I found was to set `ecx` to 0x41414141 and XOR-ing the values of `eax` and `ebx` with `ecx`.

After solving these issues it was pretty straightforward to get the flag, partial overwrite saved eip on stack by entering name of length 17, return to writeable memory, use shellcode to rotate `eipd` to become 0+1i, then mov values to eax, ebx, ecx, xor the registers and syscall(0x40) to get flag.

`ctfzone{1c34fc944c4d2911f0e85b300dc0540a}`

[buggypwn]: {{site.baseurl}}/ctf/2018-07-23-ctfzone-buggypwn/buggy_pwn.py
[exploit]: {{site.baseurl}}/ctf/2018-07-23-ctfzone-buggypwn/exploit.py
[disassembler]: {{site.baseurl}}/ctf/2018-07-23-ctfzone-buggypwn/disassembler.py
[graph]: {{site.baseurl}}/ctf/2018-07-23-ctfzone-buggypwn/code.png