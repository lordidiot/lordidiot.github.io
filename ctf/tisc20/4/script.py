from pwn import *
import subprocess as sp
import dateutil.parser as dp

r = remote("fqybysahpvift1nqtwywevlr7n50zdzp.ctf.sg", 31090)
r.sendlineafter("? ", "LdWaGOgyfbVQromGEgmzfADJYNpGEPKLUgjiudRJfMoKzpXyklQgNqSxSQeNYGsr" )

while True:
	a = r.recvuntil("servers on ", timeout=1)
	if not a:
		break
	t = dp.parse(r.recvuntil("?",drop=True).rstrip()[:-1]).strftime("%s")

	gdb = """
	gef config context.enable 0
	set follow-fork-mode parent
	set print thread-events off
	set print address off
	file ./anorocware

	set $ctr=0
	break * 0x61e210
	command 1
		x/s $rbx
		i r rsi
		quit
	end

	break * 0x661506
	command 2
		set {int}($rsp+8)=REPLACE_SEED
		continue
	end

	run
	"""

	with open("geedeebee", "w") as f:
	f.write(gdb.replace("REPLACE_SEED", str(int(t)>>0xf)))

	sleep(0.4)
	res = sp.check_output(["gdb", "-q", "-x", "./geedeebee"])
	domain = res.split("http://")[1].split("\"")[0]
	length = int(res.split("rsi")[1].split("0x")[1].split(" ")[0], 16)-len("http://")
	domain = domain[:length]
		

	log.info( domain )
	r.sendline(domain)

r.interactive()
