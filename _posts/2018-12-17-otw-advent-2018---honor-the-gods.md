---
layout: post
title: "OTW Advent 2018 - Honor the gods (fun)"
description: "Baby's first food blog"
date: 2018-12-17
tags: [ctf, blog, fun]
comments: true
---

> Today we celebrate Holiday. In honor of the Flying Spaghetti Monster, cook your best spaghetti with meatballs following the instructions linked below.
>
> Service: https://github.com/OverTheWireOrg/advent2018-honorthegods

This challenge came on the 13th day of the OverTheWire Advent 2018 CTF. This was quite a challenge for me as I've not cooked before in my life. But since it was the holidays, I thought this would be a good opportunity for me to try cooking! First thing we gotta do to start this challenge is to connect to the challenge service as given above. I took note of the ingredients and got to work.

## Preparation
Just like in any pwn challenge, you have to prep the environment before you perform the attack (cooking). I dragged my neighbour along, and headed for the nearby supermarket. There were a few types of pasta sauce, but I just decided to go with the one that says "Marinara", not sure what it is, but it had meatballs in photo, so it has to be correct. Spaghetti was easy so I just grabbed a pack. To my surprise, this bigass (compartively to other local ones) supermarket near my house that has two floors did not have any minced beef! (or at least I could not find it after many rounds of walking). With that in mind, I had to pivot, and landed myself in the other smaller supermarket that had both the minced beef and the breadcrumbs. Now all that's left is to perform the `ret_to_home` technique. There are a few approaches one could take for this. I decided to walk.
![ingredients][ingredients]


## CyberChef
Now that we've prepped the ingredients, it's time to cook. I initially added one egg for the meatballs, but that seemed kinda little (and my grandmother was nagging me), so I added another egg. Thankfully, I don't think anything went wrong from that decision. I tried to shape the meatballs in a spherical manner using the ice cream scoop, but it seems like using my hands was the best way, and the ice cream scoop was just used for measurement.
![ballo][ballo]

I had intended to do everything myself. But halfway through cooking, the process forked. My grandmother couldn't take watching how I was cooking and decided to take charge of the pasta herself (please don't deduct my points for this XD)
```
spaghetti.elf
	|_ (grandparent process) pasta 
	|
	|_ (grandchild process) meatballs
```
With the meatballs ready for cooking, I heated up the oil and threw them in. I had initially planned to only cook a few at a time. But my grandma was a bit more ambitious and threw everything in. Sadly, the nice round shape of the meatballs disappeared after being cooked in the flat pan. I'm not sure how to fix this, if anyone knows please comment. Some of the meatballs also ended up getting burnt on some sides as I couldn't handle that many in a single pan. But in general, I think they came out okay for a first attempt.
![asdf][asdf]

Afterwards, the pasta was cooked and I just needed to heat up the Prego (sponsored™) sauce and toss the meatballs in.
![fdsa][fdsa]

Finally, I just plated it and took a photo for the points!
![gib_points][gib_points]

FYI, it tasted ok and shouldn't land me in the hospital (hopefully), pretty satisfied for my first attempt at cooking


[ingredients]:{{site.baseurl}}/ctf/otwadvent18/ingredients.jpeg
[ballo]:{{site.baseurl}}/ctf/otwadvent18/ballo.jpeg
[asdf]:{{site.baseurl}}/ctf/otwadvent18/asdf.jpeg
[fdsa]:{{site.baseurl}}/ctf/otwadvent18/fdsa.jpeg
[gib_points]:{{site.baseurl}}/ctf/otwadvent18/gib_points.jpeg
