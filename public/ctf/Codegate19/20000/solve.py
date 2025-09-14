# nc 110.10.147.106 15959 

files = set(["lib_{}.so".format(i+1) for i in xrange(20000)])

with open("/tmp/exit", "r") as f:
	exits = set(f.read().split('\n'))

with open("/tmp/ls", "r") as f:
	ls = set(f.read().split('\n'))

print files.difference(exits).difference(ls)
# afterwards, run command "sh", which passes the filters
