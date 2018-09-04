---
layout: post
title: "TokyoWesterns CTF 2018 - swap Returns (pwn)"
description: ""
date: 2018-09-03
tags: [ctf, pwn]
comments: true
---

> SWAP SAWP WASP PWAS SWPA 

> nc swap.chal.ctf.westerns.tokyo 37567 (Solves: 39, 233 pts)

> [swap][swap] [+exploit.py][exploit]

This challenge is running a binary that provides three options, set, swap and exit.
```
1. Set
2. Swap
3. Exit
Your choice: 
```
These options allow us to swap the contents of any 2 addresses in the binary, but we have to ensure that they are writable addresses (so that the binary does not segfault).

## What to swap

The only addresses we know that are constant are the binary's bss section as PIE is not enabled, but we do not know the stack addresses or the libc addresses. This limits us to a very small number of useful swaps as the bss section isn't populated with a lot. The most significant things in the bss section would be the Global Offset Table (GOT), and we could arrange our swaps to make the functions in the GOT call different things. My inital idea was to swap partial sections of each of the addresses in the GOT to form a one_gadget that we can easily just call.

```
addr1 : 0xdeaddeadbabebabe
...
...
addrn : 0xcafecafebeefbeef

// If we swap (addr1+4) and (addrn+4), we can effectively swap the least signifcant 4 bytes for 
// addr1 and addrn, while keeping the most signifcant 4 bytes the same. We can change the offset
// a bit swap other addresses in the function, but generally to build an address, the highest
// bytes should be swapped first as it would destroy the lower bytes
*but this actually messes up some addresses beside it

addr1 : 0xdeaddeadbeefbeef
...
...
addrn : 0xcafecafebabebabe
```
However, I noticed that the GOT did not have the correct libc functions that I could swap till it forms a one_gadget.

## Not enough known addresses

If we only have the bss section to swap, we are very limited in what we can do. We need some leaks. My teammate (Enigmatrix) managed to find a way to leak a stack addresses, allowing us to have so many more addresses to swap around. The leak was done like so: swap `atoi` and `printf` in the GOT, now the `read_int` function will call `printf([2 bytes that the user controls])`, allowing us to write "%p" as a choice in the menu, which leaks the buffer address stored in the rsi register because of the previous function call. Now we have a lot more addresses to swap as we have a stack address leak! With this, I tried to look for the least signicant bytes on the stack that I could use to build addresses that I want. I only looked at the least significant bytes as memory addresses are generally aligned to an addresses with last 3 nibbles zero, e.g. 0xdeadbeefcafeb000. This means that the last 3 nibbles (1.5 bytes) will be generally constant. For the more significant bytes of the one_gadget I wanted to build, I could just use an existing libc address that would have most bytes correct except for the 3 least signficant bytes. After wasting a lot of time on this, I realised that even with the stack addresses, I was unable to find any useful bytes to swap around.

## Arbitrary Write!

From earlier, we know that the existing bytes that we can swap around don't seem to be enough for our purposes. We need to find a more significant way to change write bytes in memory. In order to write arbitrary bytes, we must see which parts of the program we can write input. Only two things take user input, the `read_int` function which reads 2 bytes from the user (but NULLs them before function return), and the 2 pointers we control on the stack. However, we cannot swap in a way such that we can swap the pointers we write to another part of memory. After this I was kind of stuck, so I just tried to experiment with random things. Since we know the addresses of the pointers we control on stack, I considered trying to swap our pointers itself, and I stumbled upon this interesting combination. `Where swap is swap(addr1, addr2), we run swap(addr_of_addr2, a), where a is a pointer to A`. This creates some weird swapping stuff which ends up such that now A points to the original a. 
Illustration -> * 1, 2 and 3 refer to the steps taken by the swap routine.
![paper][paper]

What can we do with this? It seems quite useless at first look but I realised that it could allow us to write 1 arbitrary byte to memory. Here's how it works.

1) First we have to find an address that contains a pointer which points to a valid address that does not get changed while we are running in main. For me I think I used this address on the stack `0x00007ffd188a9008│+0xb8: 0x00007ffd188a9078 (I will call this address A)  →  0x00007ffd188a9fd2  →  "LD_PRELOAD=./libc.so.6"`

2) We must also realise that in the bss, there are large sections that are mapped and writable which are not changed during program execution. For me I used `0x601200 - 0x6012FF`. Do you notice something? We can control the least significant byte of this address, this will come useful later.

3) Now lets do our arbitrary single byte write. If we want to write the byte `0x99`, the situation looks like this.
```
0x0000000000601299 : 0x0
0x00007ffd188a9008 : 0x00007ffd188a9078 (A)
we do a quick swap with the two addresses
0x0000000000601299 : 0x00007ffd188a9078 (A)
0x00007ffd188a9008 : 0x0

Now if you refer to my drawing, a is 0x0000000000601299, while 0x00007ffd188a9078 is A
After we do the weird swap, we end up with a situation such that now A->a, A points to a. So we end up with a circular reference
0x0000000000601299(a) -> 0x00007ffd188a9078 (A) -> 0x0000000000601299(a)

Since we have a stack leak, we know the address of A, and since we set the least significant byte of address a to be 0x99, now the byte that A points to is 0x99!
If we swap this least signicant byte away, we can essentially write any bytes we want.
```
With this technique, I could write any address. I would just write byte by byte to a temporary address like 0x601400. Then I swap 0x601400 with any address I want
```
0x601400 : 0xef
0x601400 : 0xbeef
0x601400 : 0xadbeef
0x601400 : 0xdeadbeef
then simply swap 0x6010400 with (addr)

addr : 0xdeadbeef
```

## rop rop rop to the top
Since I have an arbitrary write, I replaced the GOT entry of `exit` with a gadget that has many pops, so that it would `ret` at a part of the stack which doesn't get changed much. At that address, I used my arbitrary write to write my ROP chain, which does `puts(printf_GOT)-libc leak => main`. Once I know this libc leak I calculate the libc base address and write our one_gadget into the GOT of `exit`, note that after running main the second time, the stack is shifted slightly so stack offsets need to change slightly. Now we just call `exit` with the third option and we pop a shell! Quick note: Because our arbitrary write uses the binary's functions a lot, it would be too slow to wait for each prompt before sending our input, so we just `sendline()` instead of `sendlineafter()`, this sends our input in a big chunk that is buffered at the challenge server. My original solution waited for each prompt and it timed out before I was done with the exploit.

`TWCTF{unlimited_SWAP_Works}`

[swap]:{{site.baseurl}}/ctf/TokyoWesterns18/swap/swap_returns
[exploit]:{{site.baseurl}}/ctf/TokyoWesterns18/swap/exploit.py
[paper]: {{site.baseurl}}/ctf/TokyoWesterns18/swap/paper.jpeg