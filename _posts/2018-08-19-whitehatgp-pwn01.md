---
layout: post
title: "WhiteHatGP Quals 2018 - pwn01 (pwn)"
description: ""
date: 2018-08-19
tags: [ctf, pwn]
comments: true
---

> nc pwn01.grandprix.whitehatvn.com 26129
(Solves: 34, 160pts)
>
> [giftshop][giftshop] [+exploit.py][exploit]

This challenge provides a binary and a ptrace program that runs alongside the challenge binary. The intention of the ptrace program is to monitor the child challenge binary to block certain syscalls (execve ...) and to prevent certain filenames like `/home/gift/flag.txt` from being read with the `open` and `openat` syscalls. The challenge also prints a pointer in the `.bss` section and thus PIE doesn't matter as we have a leak.

```
welcome to an ez exploit challenge ----- author RUSSIAN CHIBI
----------------Gift shop----------------
choose whatever U want

OK First, here is a giftcard, it may help you in next time you come here !
0x5651b7e780d8
Can you give me your name plzz ??
bbbb
Enter the receiver's name plzz: 
cccc
Oh Hi what do you want bbbb?? 


----------------Gift shop----------------

1: Order
2: Show order
3: Delete order
4: Loyal customers area
5: Exit
Your choice:
```

We are first asked for a name, which is vulnerable to a format string attack.

{% highlight C %}
snprintf((char *)&orders + 96 * i, 30uLL, &name_l);
snprintf((char *)&orders + 96 * i + 30, 30uLL, &recv_l);
{% endhighlight %}

However, as far as I know, most of the important format specifiers are checked and banned. So I moved on from this vulnerability.


After exploring the binary. I notice that there is a simple buffer overflow in the `order` option when they prompt for "A letter for her/him". This buffer overflow allows us to overwrite the saved rip with at most 1.5 64-bit addresses, thus if we don't have a single win gadget we won't be able to write a proper ROP chain.

Additionally, this buffer overflow allows you to overwrite `i [$bp-0x8h]` on the stack, which is the index of the current order you are creating. By overwriting this variable with `0xffffffff = -1`, it allows us to send our `malloc()'d` chunk pointer backwards in the .bss section, close enough that we can leak it when our name is 16 bytes long. With this we are able to have a heap address leak when we show our order.
```
index: 1 - Name: bbbbbbbbbbbbbbbb�ҕ�4V - receiver: cccc 
           List item: 2  
           Price: 2 
```

Now we have a heap address leak, but how do we redirect code execution signifcantly? The solution I used was to overwrite the saved rbp on the stack with the buffer overflow I previously mentioned in the order functionality. If we overwrite the saved rbp to a location we control, i.e. some data on the heap, and we overwrite the saved rip with a `leave; ret` gadget, we can execute any ROP chain we want. I wrote my ROP chain in the address section of my order as it had an unrestrcted large write of 512 bytes.


So what ROP chain do we write? I initially tried a open-read-puts ROP chain in order to read the flag `/home/gift/flag.txt`. However, there were two issues with this. Firstly, the ptrace debugger program checks for banned file names when the `open` and `openat` sycalls are called.
{% highlight C %}
//example of the black list for sys_open
431 if (sysCall == SYSCALL_OPEN) { // open
432     string filePath = getCString(global_child_id, regs.rdi);
433     if (fileInBlackList(filePath)) {
434         gLog.log("Violation detected: opening file ", false); gLog.log(filePath);
435         mKillChild();
436         exitCode = EXIT_CODE_VIOLATION;
437         break; // do not allow syscall to finish
438     }
439 }
{% endhighlight %}
The other issue I had was that I could not find a gadget to retrieve the value of $eax after the `open` syscall, therefore I didn't know the fd that I should `read` from. However, I think this could have been possibly bruteforced.

Therefore I had to change my ROP chain. My new ROP chain used mprotect on the `.bss` section to give it RWX permissions. Then it called the `read` syscall from stdin to write to the section with RWX. Afterwards I just make my ROP chain jump to this same address. I used the previous `read` to write `execveat` shellcode to the RWX section as `execve` was blacklisted but not `execveat`.

After this we get a shell! The flag is now ours!

`WhiteHat{aeb7656b7a397a01c0d9d19fba3a81352e9b21aa}`

[giftshop]: {{site.baseurl}}/ctf/2018-08-19-whitegp-pwn01/giftshop
[exploit]: {{site.baseurl}}/ctf/2018-08-19-whitegp-pwn01/exploit.py
