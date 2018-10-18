---
layout: post
title: "Hacklu CTF 2018 - Heap Heaven 2 (pwn)"
description: ""
date: 2018-10-18
tags: [ctf, pwn]
comments: true
---

> After getting a shell last year by babbling away, this year's way to Heap Heaven is paved by talking normally. Implementing proper speech took a toll on the amount of functionality we were able to add this year, though.
>
> Good luck and have fun climbing Heap Heaven 2018!
>
> nc arcade.fluxfingers.net 1809
>
> [heap\_heaven\_2][binary] [libc.so.6][libc] [+exploit.py][exploit]

This challenge is presented as a simple menu based heap challenge like many other heap pwn challenges. We are able to write to the heap, and free from the heap. We can also leak memory from pointers in the heap.

```
Please select your action:
[1] : write to heap
[2] : alloc on heap //doesn't do anything
[3] : free from heap
[4] : leak
[5] : exit
```

## Overview
Upon reversing the binary, it reveals that heap this challenge is referring to isn't the usual heap region in memory but rather a `mmap`'d region in memory. A `state` variable exists in the .bss section which contains a pointer in the traditional heap, that contains another pointer pointing to the chunk with two function pointers `bye` and `menu`. This immediately stands out as function pointers on the heap are always targets for our heap exploits.

```
state : heap_ptr1 -> heap_ptr2 -> bye()
                               -> menu()
``` 

Another thing to notice is that while the `write_wrapper` and `leak_wrapper` are bounds checked, the `free_wrapper` function does not perform any bounds checking, which can be very useful once we are able to attain some leaks to break PIE and ASLR.

For this challenge, the libc provided was GLIBC 2.28, a super new version which doesn't seem to work with my setup. Usually when I am unable to LD_PRELOAD a libc, I just continue exploiting it with my normal libc and modify offsets later. (This turns out to be a kinda bad idea for this challenge)

## Leaking REAL Heap Addresses
Since we noticed earlier that the real heap has important function pointers and structures, our first goal should be finding the address of the heap. Through some trial and error, I noticed experimentally that the `unsorted bins` will connect with the **wilderness** of the heap. This means that one of the unsorted bins would have an arena pointer that points to the wilderness. In order to trigger this, we can fake some chunks (larger than fastbin size) in our mmapped region and free them. When we leak the resulting arena pointer in our faked chunk, we leak the address of the heap wilderness!

## Breaking PIE and ASLR
Now that we have a heap leak, what can we do with this? The first thing we can recall is that we have pointers to the functions `bye` and `menu` in the heap. Using the write and leak functionality, we can easily write the addresses in the heap where these function pointers are stored and leak them. With this knowledge, we can calculate the PIE base to defeat PIE. In the meantime, we can also use the GOT address of any libc function in order to leak the libc base address.

## Arbitrary Free
Although there aren't any bounds checking for the `free_wrapper`, we do not have a useable arbitrary free function yet as all the free calls are made as an offset from the base of the mmaped region.

{% highlight C %}
__int64 __fastcall free_wrapper(__int64 offset)
{
  free((void *)(mmapped + offset));
  return 0LL;
}
{% endhighlight %}

 In order to have a truly arbitrary free ability, we need to find the base address of this mmapped region. We can simply achieve this by leaking the pointer to the mmapped region stored in the .bss region (since we already know the PIE base).

## State your business
Now with all the leaks and our ability to free arbitray chunks, what could we do? Normally, if we had the ability to malloc chunks, we could do some manipulation to achieve an arbitrary write, allowing us to easily overwrite the function pointers in heap. However, in this case we do not have any `malloc` (or similar) control. The solution to this is to make use of the heap bin structures. In fastbins, if you free chunk A followed by chunk B, chunk B's forward pointer would point to A. So how can we use this for our exploit? If we look at the structure of `state`, we notice that the data portion of heap_ptr1 contains the address of heap_ptr2. After a free of heap_ptr1, this same location will be used as the forward pointer for the fastbin list. Thus, we can free heap_ptr1 and control the pointer in its data section!
```
state : heap_ptr1 -> heap_ptr2 -> bye()
                               -> menu()
* after freeing heap_ptr1

state : heap_ptr1 -> previously_freed_chunk -> ????
``` 
Therefore, we can setup a fake chunk in our mmapped of the same size as heap_ptr1, free that fake chunk, and now it exists in the fastbin list. If we write the addresses of the functions we wish to call in this fake chunk after freeing it, we can now control program execution! Once we free heap_ptr1, the original state will be replaced with our new faked state. In this case, I made use of the libc one_gadgets as I was not able to achieve control of the argument.

## Whoops tcache
Early I mentioned that since I was unable to LD_PRELOAD the provided libc, I worked on the challenge using my default libc. However, since I use Ubuntu 16.04, the default libc I used was version 2.23. This mean that my libc does not support tcache while the provided libc (2.28) provides tcache! When performing heap exploits, something as a big as introducing tcache will likely break everything, and that's what happened when I tried the exploit on the remote server. Luckily, for this exploit, it is possible to negate the effects of tcache, essentially allowing us to pwn the binary like it's pre-tcache. My solution for this was to fill the tcache bins for the chunk sizes I used with 7(TCACHE_MAX_BINS) chunks.

{% highlight Python %}
# fill up tcache fastbins
for i in xrange(7+1):
	write(0+i*0x20, p64(0)+p64(0x21))
for i in xrange(7):
	free(0x10+i*0x20)
{% endhighlight %}

Now that we've solved the tcache issue, we can run the exploit and get our flag!

`flag{th1s_w4s_still_ez_h3ap_stuff_r1ght?!}`

[binary]:{{site.baseurl}}/ctf/2018-10-18-hacklu-ctf-2018---heap-heaven-2/heap_heaven_2
[libc]:{{site.baseurl}}/ctf/2018-10-18-hacklu-ctf-2018---heap-heaven-2/libc.so.6
[exploit]:{{site.baseurl}}/ctf/2018-10-18-hacklu-ctf-2018---heap-heaven-2/xpl.py