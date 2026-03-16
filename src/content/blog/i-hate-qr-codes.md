---
title: "I hate QR codes"
description: ""
pubDate: 2026-03-16
tags: [random]
---

I haven't been writing much lately since nothing felt interesting enough to write about, but today I decided to rant about something on my mind.

So let's talk about **QR codes**.

## I love QR codes

QR codes are most useful as a means of `X-to-phone` communication.

They are MOST useful when `X` is some poster/billboard/screen in the **physical world**, large enough and high-quality enough that they can be scanned properly by a phone.
Usually, the only time I have difficulty scanning a QR code is when there's reflection covering the QR code.

QR codes are also really useful when `X` is another phone.
I love when apps support sharing information between users by allowing one user to scan the other user's QR code.
The process is generally really convenient and ergonomic. 

## I HATE QR codes

But as with all good things, people always take it too far.

Other than the cases I've covered above, QR codes are really annoying.
The most egregious example of this is when QR codes are used for **digital** posters.
I've seen this scenario way too many times:

![Image of QR codes being used wrongly][evil-poster]

On phones, this isn't that bad, as I can usually scan these QR codes within a few clicks (although still a few clicks too many!).
But on computers, it's SUCH a pain.
I have to copy/save the image, find a QR code tool, and then finally scan the QR code after way too many steps.
And all this time, they had many opportunities to just **share the link** alongside the poster.

I understand that sometimes the same poster is used in the physical world (hence the QR code) and shared digitally.
If there's really no way to share the link digitally, you should at least include the actual URL as text in the poster, shortened so that someone can type it in the browser manually.

## Enough is enough

Yesterday, I decided to make a change!
After reading this [nice article][shipping-at-inference-speed] about vibe coding, I saw something pretty cool:

> Folks building Mac or iOS stuff: You don’t need Xcode much anymore. I don’t even use xcodeproj files. Swift’s build infra is good enough for most things these days. codex knows how to run iOS apps and how to deal with the Simulator. No special stuff or MCPs needed.

Turns out, I can vibe code a solution for my mac pretty easily!
To solve my problem once and for all, I prompted my way to **QRSnip**.

The app is pretty simple.
You just start it and it scans a QR code for you on the screen.

<video autoplay loop muted playsinline width="100%">
  <source src="/images/i-hate-qr-codes/qr-snip-demo.mp4" type="video/mp4">
</video>

It's really cool how coding agents have made personal apps so cheap to build.

## Try it yourself

I've put the code on github so you can build it yourself if you want something like this.
Just scan the QR code below!

<center>
  <a href="https://github.com/lordidiot/QRSnip" target="_blank" rel="noopener noreferrer">
    <img src="/images/i-hate-qr-codes/qr-snip.png" alt="qr-snip" width="300">
  </a>
</center>


[evil-poster]:/images/i-hate-qr-codes/evil-poster.jpeg
[shipping-at-inference-speed]:https://steipete.me/posts/2025/shipping-at-inference-speed