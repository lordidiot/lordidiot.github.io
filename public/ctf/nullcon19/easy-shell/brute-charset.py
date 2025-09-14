from pwn import *

charset = []

for i in xrange(0x100):
	r = process("./gg")
	r.send(chr(i))
	a = r.recv(timeout=0.1)
	if "Fail" in a:
		r.close()
		continue
	else:
		r.close()
		charset.append(chr(i))
	
print charset
