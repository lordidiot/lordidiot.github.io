from pwn import *
import string
from difflib import SequenceMatcher
 
def longestSubstring(str1,str2):
	ctr = 0
	for i, j in zip(str1, str2):
		if i != j:
			break
		else:
			ctr += 1
	return ctr

		  



#context.log_level = "DEBUG"

printable = string.printable[:-5]
flag = list("TWCTF{67ced5346146c105075443add26fd7efd72763dd}")

first = [None]
if len(sys.argv) > 1:
	lb, ub = sys.argv[1].split('-')
	first = printable[printable.find(lb):printable.find(ub)+1]

best = -1

for j in first:
	r = remote("crypto.chal.ctf.westerns.tokyo", 14791)
	enc_flag = r.recvline().rstrip()[16:]
	with open("dump", "a") as f:
		f.write(enc_flag+'\n')
		f.write(''.join(flag)+'\n') 

	for i in printable:
		tmp_flag = flag[::]
		tmp_flag[''.join(flag).find('?')] = i
		if j:
			tmp_flag[''.join(flag).find('?')-1] = j
		r.sendlineafter("message: ", ''.join(tmp_flag))
		a = r.recvline().rstrip()[12:]
		with open("dump", "a") as f:
			f.write("{}{} : {} => {}\n".format(j, repr(i), a, longestSubstring(enc_flag, a)))

		if longestSubstring(enc_flag, a) > best:
			best = longestSubstring(enc_flag, a)
	r.close()

print best
	
