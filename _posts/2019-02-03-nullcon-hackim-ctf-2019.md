---
layout: post
title: "nullcon HackIM CTF 2019"
description: ""
date: 2019-02-03
tags: [ctf, pwn]
comments: true
---

This weekend my team HATS SG played in the nullcon HackIM CTF. I think this was our best performance yet in a CTF, finishing 7th! This is probably the first time we had a single-digit rank :D. I've solved a bunch of the pwn challenges so I'll talk about my solutions to them. As a team, we've solved the following challenges.

#### Pwn
- [easy-shell - Solves: ?, 451pts](#easy-shell)
- HackIM Shop - Solves: ?, 458pts
- [peasy-shell - Solves: ?, 493pts](#peasy-shell)
- babypwn - Solves: ?, 495pts
- tudutudututu - Solves: ?, 495pts

#### Crypto
- 2FUN - Solves: 72, 448pts
- GenuineCounterMode - Solves: ?, 462pts
- Singular - Solves: ?, 485pts

#### Web
- **oof**

#### Misc
- Captcha Forest - Solves: ?, 150pts
- Captcha Forest Harder - Solves: ?, 431pts
- mlAuth - Solves: ?, 475pts


# Writeups

## easy-shell
> [challenge][challenge-easy] [+exploit.py][exploit-easy]

**Disclaimer:** I was not the one who solved this during the CTF, my teammate Engimatrix solved this instead. However, I was working on a separate solution from him in parallel to have a better idea for when we want to solve the next part of the challenge 

### Overview
In short, we are given a binary that mmaps an **RWX** region, reads shellcode from the user into this region, then jumps to the shellcode. Pretty straightforward. However, there are 2 restrictions we have to bypass. Firstly, the shellcode we pass must be **alphanumeric**, in regex form: `[a-zA-Z0-9]`. Additionally, there is a seccomp rule implemented which prevents the `execve` syscall.

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x03 0xc000003e  if (A != ARCH_X86_64) goto 0005
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x01 0x00 0x0000003b  if (A == execve) goto 0005
 0004: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0005: 0x06 0x00 0x00 0x00051234  return ERRNO(4660)
```

### Approach
Just with any other shellcoding challenge, the first thing to do it search exploit-db to check if the relevant shellcode already exists. So simply google "x64 alphanumeric shellcode". There are a few samples but they all use `execve` to pop a shell, in our case, we would either need to use `execveat` or use a `open-read-write(orw)` shellcode instead. Since I could not find any such existing shellcodes, it is time to start writing our own shellcode.

With the strict restriction of only alphanumeric shellcode, my approach is always to figure out how to perform a `read` shellcode from user input into the RWX region. This is commonly referred to as a multi-stage attack, and I think it is the most effective approach to restrictive shellcoding challenges. Once we are able to perform a `read` from user input into a RWX region, we can then write a second stage payload without any restrictions! It is far easier to setup the read shellcode as opposed to the entire open-read-write chain in alphanumeric.

An important factor to consider when doing shellcoding is the context in which our shellcode runs. By this, I'm referring to the current state of the registers and memory before the first instruction from our shellcode is even executed. This is very important as it enables us to do a lot more, and reduce a lot of unnecessary instructions. To find out the state of the registers and memory, we can simply set a breakpoint using `pie break * 0xb94` in gef, and checkout the memory.
```
$rax   : 0x0               
$rbx   : 0x4000            
$rcx   : 0x00007f26a1c82260  →  <__read_nocancel+7> cmp rax, 0xfffffffffffff001
$rdx   : 0x56              
$rsp   : 0x00007fffa9d69ce8  →  0x00005652ce7e9b97  →   jmp 0x5652ce7e9b4c
$rbp   : 0x0               
$rsi   : 0x00007f26a2176000  →  "Our shellcode!"
$rdi   : 0x0               
$rip   : 0x00007f26a2176000  →  "Our shellcode!"
$r8    : 0x00007f26a1f51780  →  0x0000000000000000
$r9    : 0x00007f26a2155700  →  0x00007f26a2155700  →  [loop detected]
$r10   : 0x22              
$r11   : 0x246             
$r12   : 0x00007f26a2176000  →  "Our shellcode!"
$r13   : 0x00007fffa9d69de0  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
```

The most important registers we should look at are generally `rax, rdi, rsi, rdx` when in x64. These registers are used for the syscalls and the arguments to function calls, thus if they are already set to a good value, a lot of our work is already done for us. And indeeed, the registers are actually setup in a perfect manner for us to do a `read` syscall into the RWX region as we'd planned to do. Now all we need to do is provide a `syscall` instruction, and we can read in our second stage payload! Unfortunately, the `syscall` instruction uses the bytes `\x0f\x05`, which are not in our alphanumeric charset, how can we bypass this?

### Self-modifying shellcode
As the header suggests, we can create our `syscall` instruction in the shellcode, by making our shellcode modify itself! This is a useful technique whenever you are not able to write certain bytes. Additionally, since all our instructions are present in RWX regions, there is nothing stopping us from overwriting the instructions. After doing some research, I find that the following instructions only require alphanumeric characters to represent.
```
xor DWORD PTR [rcx + imm8], eax
push [any reg]
push imm32
pop rax
pop rcx
```
With these instructions, do you see how we can perform our self-modifiying shellcode? Since we know that we can push any registers, we can notice from above that `rsi, rip, r12` all contain a pointer to our shellcode. Thus we can simply push this value onto the stack, then pop it off into `rcx`. Now using the `push imm32` followed by a `pop rax`, we are able to get any 4 byte value (within alphanumeric range) into eax. Now we are in a perfect setup to use the `xor DWORD PTR [rcx + imm8], eax` to xor some instructions in our own shellcode! Now all we have to do is to find pairs of alphanumeric characters that xor to form `\x0f` and `\x05`. Just open up your python interpreter and do a quick bruteforce.

{% highlight Python %}
charset = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']

for i in charset:
	for j in charset:
		if ord(i)^ord(j) == 0xf:
			print "{:x}, {:x}: {:x}".format(ord(i), ord(j), ord(i)^ord(j))
{% endhighlight %}

All we have to do is make sure that imm8 and imm32 are only using alphanumeric bytes and we're good to go with forming our `syscall` instruction. Also, since we are forced to use an alphanumeric imm8, our `syscall` instruction is a bit far from the start our shellcode, so we need to use some `nop` instructions to reach that `syscall` instruction. Since the actual `nop` instruction is `\x90` (not alphanumeric), we can use a two byte nop, like `push rax; pop rax`. This achieves nothing and helps us travel down the shellcode to our syscall.

After this, our shellcode will hit the `syscall`, and read some input from the user. We simply provide an **open-read-write** shellcode that will open "flag" and print it. I will not go into detail on this and you can check my exploit source code for details.

`hackim19{to_read_or_not_to_r34d}`

[challenge-easy]:{{site.baseurl}}/ctf/nullcon19/easy-shell/gg
[exploit-easy]:{{site.baseurl}}/ctf/nullcon19/easy-shell/exploit.py

## peasy-shell
> [challenge][challenge-peasy] [+exploit.py][exploit-peasy]

### Overview
Now, after Enigmatrix had solved easy-shell, we began working on the sequel `peasy-shell`. This challenge is pretty much the same, with the big difference that the shellcode region is made **RX** before we jump to it. This is tragic as it kills our self-modifying strategy to achieve the `syscall` instruction. ... Or does it?

If you were to do a quick reversing of the `make_rx` function that they use to do this, you will notice something very important.
{% highlight C %}
int __fastcall make_rx(void *a1)
{
  int result; // eax@1

  result = mprotect(a1, 1uLL, 5);
  if ( result < 0 )
  {
    put("mprotect failed: rx");
    exit(-1);
  }
  return result;
}
{% endhighlight %}

The `len` parameter on the mprotect call is only 1! In this case, what will happen is that mprotect will round it upwards to 0x1000, however, our mmaped region is larger than 0x1000 :D. This means that we can use the same self-modifying shellcode strategy as before, just that our `syscall` instruction is 0x1000 bytes after the beginning.

### Approach
Now that we know this, we can try to modify our inital shellcode to get this working. An additional challenge is that the condition of the registers is also different from before, and our registers are no longer setup nicely for a `read` syscall. This requires a lot of weird popping and xor-ing in the stack to get our registers set nicely. I think the tricks are quite cool, so I suggest that you take a look through the shellcode and figure it out :P (feel a bit lazy to describe them thoroughly). 

After the modifications to fix the registers, we place **many** two byte nops to traverse all the way to the `syscall` instruction. Perfect! We read in our second stage payload and get the flag locally! Now lets run it on the server!

```
[+] Opening connection to pwn.ctf.nullcon.net on port 4011: Done
103
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
```
**oof**

Ah, maybe it's failing because the exploit only works 50% of the time, even locally (this is because I am using an xor trick to increment a register, this creates a situation where sometimes it decrements, and sometimes it increments).

```
[+] Opening connection to pwn.ctf.nullcon.net on port 4011: Done
103
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
```
**oof** *20 more tries

Now our shellcode should not be failing this many times, a 50% chance to work is very good already. So why does it fail 100% on remote but work locally? Then I remembered something I learnt from someone in OpenToAll in the past. When sending our data across the network, they are sometimes chunked into smaller packets before being sent across, this will happen for larger chunks of data. However, the `read` call that is initially reading our stage 1 payload will not consider this chunking, and only read the first chunk. Since our shellcode is a giant size of 0x1032 bytes (with all the nops), only a part of our shellcode is read into memory, causing the exploit to fail. So now there's only one option: **We need to make it smaller**

### Size matters
So what's interesting about this challenge is that at the end of our shellcode, the binary will add a `ret` instruction.
{% highlight C %}
*((_BYTE *)buf + v6) = 0xC3u;
{% endhighlight %}

What you may realise is, if you can push the address of our `syscall` instruction onto the stack, and get to the `ret` instruction, this is effectively a jump! Therefore, we can modify our shellcode to the xor magic to form the `syscall` instruction inside eax. Then we get that `syscall` instruction in memory using `xor DWORD PTR [rcx + imm8], eax` as before. Now just push the correct address, and we `ret` to the `syscall`! Just as before, we read in our second stage open-read-write shellcode and get the flag!

`hackim19{maybe_this_is_where_you_stop_getting_easy_shells}`

### Conclusion
I skipped a lot of details about the exploit in this writeup, if you are unclear about anything you can leave a comment or dm me or smth. The exploit used quite a lot of messing around with registers and memory so I didn't want to go into detail on everything, but I hope you can understand the main approach to these challenges `easy-shell` and `peasy-shell`. Also, I've never really been a fan of shellcoding challenges but these were really fun for me and sparked my interest shellcoding. Kudos to the author.

[challenge-peasy]:{{site.baseurl}}/ctf/nullcon19/peasy-shell/gg
[exploit-peasy]:{{site.baseurl}}/ctf/nullcon19/peasy-shell/exploit.py