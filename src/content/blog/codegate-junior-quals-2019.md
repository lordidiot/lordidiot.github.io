---
title: "Codegate Junior Quals 2019"
description: ""
pubDate: 2019-01-27
tags: [pwn, ppc]
---

This weekend I played the Codegate CTF Junior Qualfiers. I finished in 11th place and so I'll writeup the two challenges that I've solved from the qualifiers.

# MIC check
> Let the hacking begins ~ (Solves: ?, 3.0 pts)
>
> Decode it :
> 
> 9P&;gFD,5.BOPCdBl7Q+@V'1dDK?qL

Looks like some encoding format, it has too many different special characters so it can't be base64. Try base85.

`Let the hacking begins ~` \*turns out the description has the flag itself



# 20000
> nc 110.10.147.106 15959 (Solves: ?, 6.8 pts)
>
> [challenge.zip][challenge] [+solve.py][solve]

The challenge provides us with the main driver binary and 20000 accompanying .so files.

```C
printf("INPUT : ", 0LL, &v13);
__isoc99_scanf("%d", &v8);
if ( (signed int)v8 <= 0 && (signed int)v8 > 20000 )
{
printf("Invalid Input");
exit(-1);
}

sprintf(&s, "./20000_so/lib_%d.so", v8);
handle = dlopen(&s, 1);

if ( handle )
{
	v5 = handle;
	v9 = (void (__fastcall *)(void *, const char *))dlsym(handle, "test");
	if ( v9 )
	{
	  v9(v5, "test");
	  dlclose(handle);
	  result = 0LL;
	}
	else
	{
	  v6 = dlerror();
	  fprintf(stderr, "Error: %s\n", v6);
	  dlclose(handle);
	  result = 1LL;
	}
}
```

This is pretty straightforward to reverse. In short, the program requests a number from the user. The corresponding .so file will then be loaded into memory. For example, if the user provides the number `1337`, then `./20000_so/lib_1337.so` will be loaded into memory. The `test` function from this shared object will then be called.

Now that we understand the driver program, it will be a good idea to open up a few of the shared objects to see what they are doing. Reversing the `test` function from `lib_4323.so` gives the following code.

```C
puts("This is lib_4323 file.");
puts("How do you find vulnerable file?");
read(0, &buf, 0x32uLL);
system("exit");
```

`lib_1337.so` has the following in the test function

```C
handle = dlopen("./20000_so/lib_14562.so", 1);
if ( handle )
{
	v4 = (void (__fastcall *)(char *, char *))dlsym(handle, "filter1");
	v7 = dlopen("./20000_so/lib_6726.so", 1);
	if ( v7 )
	{
		v5 = (void (__fastcall *)(char *))dlsym(v7, "filter2");
		puts("This is lib_1337 file.");
		puts("How do you find vulnerable file?");
		read(0, &buf, 0x32uLL);
		v4(&buf, &buf);
		v5(&buf);
		sprintf(&s, "ls \"%s\"", &buf, v4);
		system(&s);
		dlclose(handle);
		dlclose(v7);
		result = 0LL;
	}
	else
	{
		v2 = dlerror();
		fprintf(stderr, "Error: %s\n", v2, v4);
		result = 0xFFFFFFFFLL;
	}
}
else
{
	v0 = dlerror();
	fprintf(stderr, "Error: %s\n", v0);
	result = 0xFFFFFFFFLL;
}
```

While these two might look quite different, there can be a few observations and assumptions we can make. Seeing that both .so files call `system`, we can probably assume that that should be the case for the other .so files too. We can crudely verify this by running `grep -rnw "system" | wc -l`, which shows us `20000`, a good indication that all the files at least have the string "system" in them and are likely to call the function. Another observation that can be made is that the .so files may also call filter functions from other .so files.

With this in mind, we should try to figure out how to automate the criteria for determining if a shared object's test function will be exploitable. This is the main difficulty of the challenge. There are two aspects we can consider for this, if a filter function is loose, that may allow for us to provide arbitrary system commands. The other case would be the shared object calling the `system` function with an argument that allows us to control code execution. In order to proceed, I decided to open up more shared objects to find more patterns.

## Patterns
After opening more shared objects, I noticed that there are 2 general patterns that appear. The binaries all either called `system("ls \"%s\"")` where `%s` is user input, OR `system("exit")`. Now in this case, we know for sure that `system("exit")` is not going to allow us any arbitrary control on it's own.

Since we know that shared objects with `system("exit")` will be useless, let's try to prune out these shared objects in order to reduce our number of potential vulnerable files.

I was originally thinking of using some frameworks or other complicated scripting in order to determine the argument of system. However, I was lazy to learn something new and so I made a greedy assumption, "binaries that do not call `system("exit")` will not contain the string `exit`". I can simply list the binaries that contain exit using `grep -rnw "exit"` which gives me 15000 matches already. This looks like good progress!

Now the next thing we would have to consider are the shared objects that use `system("ls \"%s\"")`. Now these might be exploitable as they contain some portion of user input. If the user is able to supply backticks or double quotes, we could escape the argument and call arbitrary sh commands. Thus we would have to figure out if the filter functions blocked these characters. This seemed complicated, so I wanted to first check whether there was a third possible argument that is passed into system, other than `ls` and `exit`. I did the same command `grep -rnw "ls \"%s\""` and to my surprise it gave me 4999 matches! Immediately, I knew I had gotten the answer. Earlier I had pruned 15000 shared objects, now that I remove 4999 objects, I am only left with one! The only remaining shared object file is `lib_17394.so`. Quickly reversing this shows us that it has the following lines.

```C
sprintf(&s, "%s 2 > /dev/null", &buf, v4);
system(&s);
```

We can run any arbitrary command! However, it does in fact have a filter that filters out some characters and the string `bash`. One string that bypasses this is simply "sh". With this, we can pop a shell and get the flag!

`flag{Are_y0u_A_h@cker_in_real-word?}`


# algo_auth
> I like an algorithm 
>
> nc 110.10.147.104 15712 
>
> nc 110.10.147.109 15712 (Solves: ?, 7.0 pts)
>
> [+smth.py][smth]

## Challenge Summary
```
==> Hi, I like an algorithm. So, i make a new authentication system.
==> It has a total of 100 stages.
==> Each stage gives a 7 by 7 matrix below sample.
==> Find the smallest path sum in matrix, 
    by starting in any cell in the left column and finishing in any cell in the right column, 
    and only moving up, down, and right.
==> The answer for the sample matrix is 12.
==> If you clear the entire stage, you will be able to authenticate.

[sample]
99 99 99 99 99 99 99 
99 99 99 99 99 99 99 
99 99 99 99 99 99 99 
99 99 99 99 99 99 99 
99  1  1  1 99  1  1 
 1  1 99  1 99  1 99 
99 99 99  1  1  1 99
```

Essentially, we have to find a path from a square on the left column travel to the right column using the least sum possible. Then we submit this sum and repeat 100 times. This obviously has to be automated as it's pretty impossible to do 100 by hand within the timeframe.

Having done some PPC stuff before, I immediately thought of using [Djikstra](https://en.wikipedia.org/wiki/Dijkstra%27s_algorithm) to solve this challenge. Djikstra is a graph theory algorithm which allows us to find the shortest path between two nodes in a graph. To adapt it to this challenge, we can assign the weight or distance between two nodes to just be the number on the node. For example with the following board
```
1 2 3
4 5 6
7 8 9
```
We can just say that the distance to go from 1 to 2 is 2 units. This allows us to apply Djikstra to find the lowest sum path between the starting and ending node.

Now that we can find the lowest sum path between 2 nodes, we just need to repeat this for every possible starting and ending point and find the minimum sum as our answer. I didn't implement the solution for this challenge and just took the code from a nice site I like to use called [GeekForGeeks](https://www.geeksforgeeks.org/dijkstras-shortest-path-algorithm-greedy-algo-7/).

After solving 100 levels, the server tells us "@@@@@ Congratz! Your answers are an answer". Thus we simply have to convert each answer to it corresponding ASCII character to get a base64 encoded flag!

`g00ooOOd_j0B!!!___uncomfort4ble__s3curity__is__n0t__4__security!!!!!`

[solve]:/ctf/Codegate19/20000/solve.py
[smth]:/ctf/Codegate19/algo_auth/smth.py
[challenge]:/ctf/Codegate19/20000/challenge.zip