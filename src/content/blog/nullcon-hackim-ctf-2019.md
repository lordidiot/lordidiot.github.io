---
title: "nullcon HackIM CTF 2019"
description: ""
pubDate: 2019-02-03
tags: [ctf, pwn]
---

This weekend my team HATS SG played in the nullcon HackIM CTF. I think this was our best performance yet in a CTF, finishing 7th! This is probably the first time we had a single-digit rank :D. I've solved a bunch of the pwn challenges so I'll talk about my solutions to them. As a team, we've solved the following challenges.

#### Pwn
- [easy-shell - Solves: ?, 451pts](#easy-shell)
- [HackIM Shop - Solves: ?, 458pts](#hackim-shop)
- [peasy-shell - Solves: ?, 493pts](#peasy-shell)
- [babypwn - Solves: ?, 495pts](#babypwn)
- [tudutudututu - Solves: ?, 495pts](#tudutudututu)

#### Crypto
- 2FUN - Solves: ?, 448pts
- [GenuineCounterMode - Solves: ?, 462pts](https://github.com/Ariana1729/CTF-Writeups/tree/master/2019/nullcon/GenuineCounterMode)*
- [Singular - Solves: ?, 485pts](https://github.com/Ariana1729/CTF-Writeups/tree/master/2019/nullcon/Singular)*

#### Rev
- [0bfusc8 much - Solves: ?, 497pts](https://daniellimws.github.io/obfusc8.html)*

#### Web
- **oof**

#### Misc
- [Captcha Forest - Solves: ?, 150pts](https://tcode2k16.github.io/blog/posts/2019-02-03-nullcon-hackim-writeup/#captcha-forest)*
- [Captcha Forest Harder - Solves: ?, 431pts](https://tcode2k16.github.io/blog/posts/2019-02-03-nullcon-hackim-writeup/#captcha-forest-harder)*
- [mlAuth - Solves: ?, 475pts](https://tcode2k16.github.io/blog/posts/2019-02-03-nullcon-hackim-writeup/#mlauth)*

*external links

# Writeups

## easy-shell
> Go get yourself a shell while it's possible
>
> nc pwn.ctf.nullcon.net 4010
>
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

```python
charset = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']

for i in charset:
	for j in charset:
		if ord(i)^ord(j) == 0xf:
			print "{:x}, {:x}: {:x}".format(ord(i), ord(j), ord(i)^ord(j))
```

All we have to do is make sure that imm8 and imm32 are only using alphanumeric bytes and we're good to go with forming our `syscall` instruction. Also, since we are forced to use an alphanumeric imm8, our `syscall` instruction is a bit far from the start our shellcode, so we need to use some `nop` instructions to reach that `syscall` instruction. Since the actual `nop` instruction is `\x90` (not alphanumeric), we can use a two byte nop, like `push rax; pop rax`. This achieves nothing and helps us travel down the shellcode to our syscall.

After this, our shellcode will hit the `syscall`, and read some input from the user. We simply provide an **open-read-write** shellcode that will open "flag" and print it. I will not go into detail on this and you can check my exploit source code for details.

`hackim19{to_read_or_not_to_r34d}`

[challenge-easy]:/ctf/nullcon19/easy-shell/gg
[exploit-easy]:/ctf/nullcon19/easy-shell/exploit.py

## peasy-shell
> one more easy shell for free!
>
> nc pwn.ctf.nullcon.net 4011
>
> [challenge][challenge-peasy] [+exploit.py][exploit-peasy]

### Overview
Now, after Enigmatrix had solved easy-shell, we began working on the sequel `peasy-shell`. This challenge is pretty much the same, with the big difference that the shellcode region is made **RX** before we jump to it. This is tragic as it kills our self-modifying strategy to achieve the `syscall` instruction. ... Or does it?

If you were to do a quick reversing of the `make_rx` function that they use to do this, you will notice something very important.
```c
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
```

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
```c
*((_BYTE *)buf + v6) = 0xC3u;
```

What you may realise is, if you can push the address of our `syscall` instruction onto the stack, and get to the `ret` instruction, this is effectively a jump! Therefore, we can modify our shellcode to the xor magic to form the `syscall` instruction inside eax. Then we get that `syscall` instruction in memory using `xor DWORD PTR [rcx + imm8], eax` as before. Now just push the correct address, and we `ret` to the `syscall`! Just as before, we read in our second stage open-read-write shellcode and get the flag!

`hackim19{maybe_this_is_where_you_stop_getting_easy_shells}`

### Conclusion
I skipped a lot of details about the exploit in this writeup, if you are unclear about anything you can leave a comment or dm me or smth. The exploit used quite a lot of messing around with registers and memory so I didn't want to go into detail on everything, but I hope you can understand the main approach to these challenges `easy-shell` and `peasy-shell`. Also, I've never really been a fan of shellcoding challenges but these were really fun for me and sparked my interest shellcoding. Kudos to the author.

[challenge-peasy]:/ctf/nullcon19/peasy-shell/gg
[exploit-peasy]:/ctf/nullcon19/peasy-shell/exploit.py

## HackIM Shop
> Welcome to our bookstore, check if you find anything interesting.
>
> nc pwn.ctf.nullcon.net 4002
>
> [challenge][challenge-hackim] [+exploit.py][exploit-hackim] [+libc6_2.27-3ubuntu1_amd64.so][libc-hackim]

### Overview
Menu pwnable! My fav <3
```
NullCon Shop
(1) Add book to cart
(2) Remove from cart
(3) View cart
(4) Check out
> 
```

After reversing the binary, I noticed that the `remove_book` functionality did not clear up the pointer for a book in the list of books after freeing the memory. This is a use-after-free of (UAF) bug. Now we should check out the structure of a book to see what we could possible exploit if we can control the chunk.
```c
struct book{
    QWORD index;
    char * data;
    QWORD price;
    char copyright[32];
}
```

Now the `copyright` buffer is something interesting to us. If you look at the `print_books` functionality, there is the following line.

```c
printf(books[i]->copyright);
```

Usually, this buffer will only contain "Copyright NullCon Shop". However, should we be able to control this value, this is a classic format string vulnerability.

### Exploitation
Now that we are aware of two big vulnerabilities, we can see the path we should take for exploitation. We should somehow make use of this UAF vulnerability to control the contents of the copyright buffer, then we can do quite a lot with the format string vulnerability. So how can we control this UAF? We can make use of the heap's fitting logic, which allows us to have the data pointer of one chunk point to a book. Then we can write any arbitrary pointer we one in that fake book.
```
make two books, with data size 0x10
[ 0x38 bytes ] BOOK_1
[ 0x10 bytes ] DATA_1
[ 0x38 bytes ] BOOK_2
[ 0x10 bytes ] DATA_2

after we free both books
  0x38 bytes   BOOK_1
  0x10 bytes   DATA_1
  0x38 bytes   BOOK_2
  0x10 bytes   DATA_2

Now if we were to allocate a new book with data of size 0x38 instead...
[ 0x38 bytes ] BOOK_1
  0x10 bytes   unused
[ 0x38 bytes ] DATA_1 and BOOK_2
  0x10 bytes   unused
```
With this setup, we control all the members of BOOK_2, including the `copyright` buffer! Since we also control the data pointer for BOOK_2 through the contents of DATA_1, we can leak the libc addresses using the `data` pointer of BOOK_2. After leaking, we can figure out the libc version using tools like niklasb's [libc-db](https://github.com/niklasb/libc-database).

After this, we can try to exploit the format string vulnerability. The first thing we do is to check what the stack looks like during the printf call. If we can control any pointers within the stack when the printf is called, this allows to have an arbitrary write or read primitive. And indeed, we do! Luckily for us, when the printf call occurs, the index of the book is on the stack, since we control the book structure, we can write any arbitrary pointer as the index.

With this arbitrary read and write primitive. I began to exploit this challenge using the `house-of-spirit` technique inside the Global Offset Table (GOT). I used the format string vuln to write the correct size bytes in the GOT. Then, by freeing the fake BOOK_2 that we created, I could also achieve an arbitrary free. With these two combined, I could arbitrarily free the fake chunk that I placed within the GOT. Now, when I allocated a new book, it's data pointer would point inside the GOT, allowing me to write many `one_gadgets` inside the GOT that would pop a shell for me!

`hackim19{h0p3_7ha7_Uaf_4nd_f0rm4ts_w3r3_fun_4_you}`

[challenge-hackim]:/ctf/nullcon19/HackIM_Shop/challenge
[exploit-hackim]:/ctf/nullcon19/HackIM_Shop/exploit.py
[libc-hackim]:/ctf/nullcon19/HackIM_Shop/libc6_2.27-3ubuntu1_amd64.so

## babypwn
> Can you exploit the basic bugs?
>
> nc pwn.ctf.nullcon.net 4001
>
> [challenge][challenge-babypwn] [+exploit.py][exploit-babypwn]

### Overview
This challenge was actually quite straightforward. And I'm a bit surprised it didn't have more solves (I found HackIM harder), maybe it's because the scanf trick was not so known. Regardless here is the solution I used. The challenge has two vulnerabilities. Firstly, there is the format string vulnerability in the name.
```c
_isoc99_scanf("%50s", format + 14);
...
printf(format); // vulnerable pattern!
```
This allows us to use "%p" to leak pointers present in the stack. Thus we can leak a libc pointer in the stack and bypass ASLR to find the libc base in memory.

```
Create a tressure box?
Y
name: %p.%p.%p.%p.%p
How many coins do you have?
0
Tressure Box: 0x1.0x7fc685178790.0x10.(nil).(nil) created!
```

The second vulnerability is the signed check when asking for the number of coins we want.
```c
if ( (char)numcoins > 20 )  // signed
{
    perror("Coins that many are not supported :/\r\n");
    exit(1);
}
```
If we provided a negative `numcoins` like `0xff (-1)`, this would pass the signed check, but the following for loop would treat `numcoins` as an unsigned variable, allowing us to write `0xff (255)` dwords in the stack. This means we can overwrite the saved `rip` in stack (just like a buffer overflow). 

```c
for ( i = 0; i < numcoins; ++i ) // unsigned
{
    v8 = &v15[4 * i];
    _isoc99_scanf("%d", v8);
}
```

However, there is also a stack canary! If we overwrite this with a wrong value, this will cause the program to exit prematurely before returning, which ruins our exploit. Now we can bypass this canary if we can leak it, like through the format string vulnerability. However, the format string is only printed after we've specified all the coins, thus we cannot know the canary when writing. This requires knowledge of a cool scanf trick. When scanf is called like so:

```c
scanf("%d", ...);
```

You can provide the characters `-` or `+`, and the scanf will not change the value of the variable. Thus, we can use this to not destroy the canary while overwriting the saved rip. Afterwards, we just need to change saved `rip` back to main, so we can overflow one more time to return to a `one_gadget`.

`hackim19{h0w_d1d_y0u_g37_th4t_c00k13?!!?}`

[challenge-babypwn]:/ctf/nullcon19/babypwn/challenge
[exploit-babypwn]:/ctf/nullcon19/babypwn/exploit.py


## tudutudututu
> I found a ToDo service to maintain my daily tasks. My life is sorted now!
>
> nc pwn.ctf.nullcon.net 4003
>
> [challenge][challenge-tudu] [+exploit.py][exploit-tudu]

```
Menu:
(1) Create a new todo
(2) Set description for a todo
(3) Delete an existing todo
(4) Print todos
(5) Exit

> 
```
Another heap menu pwnable! 

### Overview
This challenge is supposed to be a program to create todos to remember things. When creating a new todo, the program does a simple `malloc(0x10)` followed by a `strdup(user_input)`, creating 2 chunks in the heap.

```
[ 0x10 bytes ] todo_1
[ 0x? bytes ] topic_1
```

The structure of the todo is as follows:

```c
struct todo{
    char * topic;
    char * description;
}
```

Now after we initialise the todo with a topic, we have the additional option of adding a description to the todo, this will allocate a new chunk and set the pointer to the chunk in the struct of the todo. The fatal error however, is that this description pointer is not initialised to zero when a todo is created. This means that if there is leftover data in the chunk when it was allocated, the program will think that it is the description pointer. When we reverse the `delete` functionality, we can see these lines of code.

```c
if ( desc )
    free(desc);
free(_todo);
```

Thus, if we can control the value of this uninitialised description member, we can exploit it through the `delete` functionality of the program. In essense, should we control this description member, we have an arbitrary free primitive.

### Exploitation
Now that we understand the main bug, we can try to exploit this. The steps to exploit the uninitialised member are as follows.
```
create new todo, with 0x10 byte topic
[ 0x10 bytes ] todo_1
[ 0x10 bytes ] topic_1

free this todo
  0x10 bytes   old_todo_1
  0x10 bytes   old_topic_1

allocate 2 new todos, with topics larger than 0x10 bytes
[ 0x10 bytes ] todo_2
[ 0x10 bytes ] todo_3 !! ( this used to be old_topic_1 )
[ 0x? bytes ] topic_2
[ 0x? bytes ] topic_3
```

As we can see from this scenario, `todo_3` uses the same chunk that `topic_1` previously used. In this case, we can write an address at the 8 byte offset of `topic_1`, this will then be used as the description of `todo_3` later on. With this primitive, we can arbitrarily read any address, and free any address. Since we can leak any address, I utilised this to leak the heap address and the libc base.

### rip control
Now that we have all the leaks we probably will ever need, we need to figure out how to control `rip` to change program execution. How I did this was to transition our arbitrary free to a `fastbin double free`. Since we knew the address of the heap, we could create 2 todos that had descriptions or topics pointing to the same chunk. If we freed both these todos, we would thus create a circular fastbin list, allowing us to perform a `fastbin attack`. Now to utilise this `fastbin attack` to control `rip`, I made it return an arbitrary chunk before the location of `__malloc_hook`. This allows me to overwrite the value of `__malloc_hook` with a `one_gadget`. And that gets us our shell!

`hackim19{D0nt_f0r93t_t0_1ni7i4liz3}`

[challenge-tudu]:/ctf/nullcon19/tudutudututu/challenge
[exploit-tudu]:/ctf/nullcon19/tudutudututu/exploit.py
