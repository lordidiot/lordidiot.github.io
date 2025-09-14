import sys
from pwn import u32
from urllib import unquote
from Crypto.Util.number import long_to_bytes, bytes_to_long

def nthroot(y, n):
	x, xp = 1, -1
	while abs(x - xp) > 1:
		xp, x = x, x - x/n + y/(n * x**(n-1))
	while x**n > y:
		x -= 1
	return x

with open(sys.argv[1]) as f:
	keydetails = long_to_bytes(nthroot(bytes_to_long(f.read()), 3))

key = unquote(keydetails.split("EncKey=")[1].split("&")[0])
iv = unquote(keydetails.split("EncIV=")[1].split("&")[0])

key_addr = 0x0000000000951DF0
iv_addr  = 0x0000000000951DD0
for i in xrange(4):
	print "set {int}"+"{}={}".format(key_addr+i*4, u32(key[i*4:(i+1)*4]))
	print "set {int}"+"{}={}".format(iv_addr+i*4, u32(iv[i*4:(i+1)*4]))
