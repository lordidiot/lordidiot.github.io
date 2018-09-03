from subprocess import PIPE, Popen
import string
import sys
import time

def cmdline(command):
    process = Popen(
        args=command,
        stdout=PIPE,
        shell=True
    )
    return process.communicate()[0]

flag = "TWCTF{base64_rot13_uu}"
flag = list(flag)
printable = sorted(list(string.printable[:-6]))
printable.remove('"')
printable.remove("'")
printable.remove("`")
printable.remove("<")
printable.remove(">")
printable.remove("\\")
printable.remove("|")
printable.remove("&")
printable.remove("(")
printable.remove(")")
printable.remove(",")
printable.remove("$")
printable.remove(";")


script = ""

with open("./script", "r") as f:
	script = f.read()

for c in "tuvw":
	for ch in printable:
		tmp_flag = flag
		tmp_flag[20] = c
		tmp_flag[21] = ch
		with open("tmp_script", "w") as f:
			f.write(script.replace("FLAG_HERE", "".join(tmp_flag)))
			f.close()	
		print "{}{} => {}".format(c,ch, cmdline("gdb -q -x tmp_script").split('\n')[3].split('\t')[1])
