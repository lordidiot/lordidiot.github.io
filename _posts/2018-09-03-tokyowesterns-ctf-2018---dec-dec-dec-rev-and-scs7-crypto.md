---
layout: post
title: "TokyoWesterns CTF 2018 - dec dec dec (rev) and scs7 (crypto)"
description: ""
date: 2018-09-03
tags: [ctf, rev, crypto]
comments: true
---

These were two different challenges, but I solved them with similar methods.

# dec dec dec
> [dec_dec_dec][dec_dec_dec] [+test.py][test] [+gdbscript][gdb] (Solves: 159, 99 pts)

This challenge is a simple reverse challenge that takes our input as a parameter `./dec_dec_dec flag_string_is_here`, encrypts it with some functions, and does a string compare to the encrypted flag in memory. Upon reading the decompiled code, I saw that it encrypted the flag with three different functions. It was quite late in the night when I did the challenge, so I could be bothered with doing any static analysis. (After the solving the challenge, I realised that static analysis would have been an easy way to solve this too). Instead, I tried this challenge as a black box encryption challenge. I threw some random input as a flag and looked at the encrypted output. I noticed that the longer the flag we gave it, the longer the encrypted text, so it was unlikely that these were some hashing functions.

```
FLAG : ENC
"Lord" : "(1U0Y;$U./3T "
"Lord_Idiot" : "01U0Y;$U3.5=-5'EI<4X]/0  "
"Lord_Idiot_Is_Cool" : "81U0Y;$U3.5=-5'EI<5,Y5W Q.5%O,CEF"
```

When I see such types of encryption, I always try to get a partially correct answer. Since we know that the flag format is `TWCTF{flag}`, I tried to encrypt `TWCTF{AAAAAAAAAA}`

```
FLAG : ENC
"TWCTF{AAAAAAAAAA}" : "925-Q44E233=$2%-/1$A33T1(4T]$2S ],0  "
correct_flag : "@25-Q44E233=,>E-M34=,,$LS5VEQ45)M2S-),7-$/3T "
```
`25-Q44E233=` is the same for both encrypted strings! This indicates that generally, for each character correct in the user input, there would be more characters in the encrypted output that are the same as the encrypted flag. This allows us to bruteforce the flag, character by character. However, since the size of the encrypted string is not the same as the user string, the relationship isn't 1-1, and so sometimes you may get an increase in correct encrypted characters even when you input the wrong character string. The only way to solve this is to bruteforce 2 characters together, and to see which encrypted output is the best. It's unlikely that 2 two-byte character pairs can both be equally correct when encrypted.

To facillitate this bruteforce, I wrote a quick gdb script that extracts the encrypted strings, so I wouldn't have to reimplement the encryption functions. Then I used a python script to keep calling the gdb script and parsing the output. This gives us the flag!

`TWCTF{base64_rot13_uu}` 

_After seeing the flag, I felt quite stupid for not doing static analysis lol._


# scs7
> nc crypto.chal.ctf.westerns.tokyo 14791

> Note: You can encrypt up to 100 messages "per once connection". 

> [+solve.py][solve] (Solves: 134, 112 pts)

When we connected to the service, we are greeted by some sort of encryption service again. This time it's actually a black-box encryption service :P.
```
encrypted flag: Q9B1mAZTrgkqJHhhWyU5PhAJFpjvCaWZZ3uH1bJ24dDVD6FaiE95EBNV4K2WDEGh
You can encrypt up to 100 messages.
message: A  
ciphertext: rq
message: AA 
ciphertext: Hwa
message: AAA
ciphertext: vPAP
```
Similar to dec_dec_dec, the flag is encrypted and we are shown the encrypted flag. However, each time you connect to the service, you are provided with a different encrypted flag. We know that the flag has to always be the same, so this indicates that the encryption uses some sort of key. Like earlier for dec_dec_dec, since the encrypted string changes length with our user input, I guessed that it should be any hashing algorithm or something of that sort. So I send a partially correct flag again and see the output.
```
encrypted flag: GBCP9XLfnA0Fs377xpkJc7XsiT6tUYxLLZS3PMsRKru8uQiYoeBJeC48K2RxueV7
You can encrypt up to 100 messages.
message: TWCTF{give_flag}
ciphertext: gKYyAAiQpztE7maTfq3zzv
```
Oh no. There isn't any noticeable similarities between the encrypted output and the correct one. But it's still too early to give up, so I guess that maybe the input length is significant in this form of encryption, and I try different lengths of the same `TWCTF{...}` string.
```
encrypted flag: Jo7ML2TwGVY4eyaaqBSDha2esZvnirqTT61yMRef0cHgHjsrxdoDd7tg0PfqHdua
You can encrypt up to 100 messages.
message: TWCTF{AAAAAAAAAAAAAAAAAA}  
ciphertext: 6xGHb0ABYSLx69cwVdWVAGkv9osderXmSE
message: TWCTF{AAAAAAAAAAAAAAAAAAAAAA}
ciphertext: GSut4hDBf8JvZbbbzmyDKj4FZxqL3RUxCiSEBen9
message: TWCTF{AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA}
ciphertext: Jo7ML2TwA2SMiaHCBcC0QSD0Jr0Nr02CXRBof1swCn50D7XtbgRNL7KEVoD9Pr5u
```
Jackpot! Given a flag of length 47, the encrypted output seems very similar, with both having `Jo7ML2Tw` the same, at the start. Since we know that only the start of our input is correct, it makes sense that the start of the encrypted output is correct. This encryption algorithm thus is quite similar to dec_dec_dec in the sense that each correct character would lead to more correct characters in the encrypted output. Knowing this, we use a similar technique to bruteforce the flag. I also improved my script so that I could perform the two-character brute a bit more efficiently. I modified the script by hand for each iteration but it was quite brainless work so it was not that difficult. My work flow looked like this.
![workflow][screenshot]

`TWCTF{67ced5346146c105075443add26fd7efd72763dd}`

[dec_dec_dec]:{{site.baseurl}}/ctf/TokyoWesterns18/dec/dec_dec_dec
[gdb]:{{site.baseurl}}/ctf/TokyoWesterns18/dec/script
[test]:{{site.baseurl}}/ctf/TokyoWesterns18/dec/test.py

[solve]:{{site.baseurl}}/ctf/TokyoWesterns18/scs7/solve.py
[screenshot]:{{site.baseurl}}/ctf/TokyoWesterns18/scs7/screenshot.png