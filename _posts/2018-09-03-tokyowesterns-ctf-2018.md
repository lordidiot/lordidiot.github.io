---
layout: post
title: "TokyoWesterns CTF 2018"
description: ""
date: 2018-09-03
tags: [ctf, blog]
comments: true
---

I played this years TokyoWesterns CTF with team [HATS Singapore][ctftime] and we finished in 58th place with 925 points. We solved the following challenges and I've written writeups for the ones I've solved.

- [swap Returns (pwn)][swap] - Solves: 39, 233 pts
- [load (pwn)][load] - Solves: 49, 208 pts
- Shrine (web) - Solves: 58, 190 pts
- [scs7 (crypto)][scs7] - Solves: 134, 112 pts
- [dec dec dec (rev)][dec] - Solves: 159, 99 pts
- Welcome!! (warmup) - Solves: 799, 28 pts

Additional writeup for Neighbour C which I solved after the CTF
- [Neighbour C (pwn)][neighbour]

## Some thoughts

This CTF was very fun for me as the difficulty of the challenges wasn't too extreme that I was pulling my hair out (since I was doing the lower point challenges), but they were definitely still challenging. Burnt my whole weekend on it though lol.

After the CTF, I realised that I do pwns really slowly and my workflow is definitely something that I need to improve. This is most prevalent for my gdb usage. For PIE binaries like neighbour(my exploit worked locally but kept segfaulting in remote T^T), I kept having to `vmmap` and then manually dereference the pie base with the added offset I wanted to look at. For one or two times this might not be too big of a problem, but if I am working on a challenge for hours and I keep doing that, it will definitely be too slow. I'm not sure if GEF has a function for this and I'm just being stupid but if it doesn't i'll probably try to implement it as an extension command in the near future.

Also about playing with HATS. I initially joined HATS a few months ago after being invited from by the organisers of a local CTF I joined. It's supposed to be an open community for other Singaporeans interested in security and such. I was hoping it would be quite active in CTFs considering that the admins are CTF players themselves. But recently it's mostly been just a bunch of us kids playing by ourselves, and the better players being too busy with life stuff. I don't blame them but it's not really what I was hoping for. Before playing with HATS, I played with OpenToAll. Playing with OpenToAll was a LOT better than when I was playing solo but I was too slow to solve anything since I mostly like to do pwns. I can't solve the hard pwns that less people try and I'm too slow for the easier pwns that everyone works on, but at least they have many people playing each CTF. I mean, of course I could continue working on challenges even after others solve them, but there isn't a lot of satisfaction solving a challenge that your teammate has already solved, also it's wasting time if we want to get more points. On the other hand, when I play with HATS, not many people turn up for each CTF (TokyoWesterns was basically me and another guy mostly). On the bright side, this gives me all the time I want to solve the challenges since no one else is doing them, but it's not really that fun to get >50th place everytime, even though I know that some challenges are solvable, just that we lack the manpower to solve them within CTF time. So now I'm conflicted whether to continue playing with HATS (more time for me to practice, less teammates, worse results generally), or OpenToAll(less time for me to solve chals, a LOT more teammates, generally perform better).


[ctftime]:https://ctftime.org/team/58574
[swap]:{{site.baseurl}}/2018-09-03/tokyowesterns-ctf-2018-swap-returns-pwn/
[load]:{{site.baseurl}}/2018-09-03/tokyowesterns-ctf-2018-load-pwn/
[scs7]:{{site.baseurl}}/2018-09-03/tokyowesterns-ctf-2018-dec-dec-dec-rev-and-scs7-crypto/
[dec]:{{site.baseurl}}/2018-09-03/tokyowesterns-ctf-2018-dec-dec-dec-rev-and-scs7-crypto/
[neighbour]:{{site.baseurl}}/2018-09-04/tokyowesterns-ctf-2018-neighbour-c/