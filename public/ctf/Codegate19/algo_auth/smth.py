# Python program for Dtra's single 
# source shortest path algorithm. The program is 
# for adjacency matrix representation of the graph 
from pwn import *
# Library for INT_MAX 
import sys 

class Graph(): 

	def __init__(self, vertices): 
		self.V = vertices 
		self.graph = [[0 for column in range(vertices)] 
					for row in range(vertices)] 

	# A utility function to find the vertex with 
	# minimum distance value, from the set of vertices 
	# not yet included in shortest path tree 
	def minDistance(self, dist, sptSet): 

		# Initilaize minimum distance for next node 
		min = sys.maxint 

		# Search not nearest vertex not in the 
		# shortest path tree 
		for v in range(self.V): 
			if dist[v] < min and sptSet[v] == False: 
				min = dist[v] 
				min_index = v 

		return min_index 

	# Funtion that implements Dtra's single source 
	# shortest path algorithm for a graph represented 
	# using adjacency matrix representation 
	def dtra(self, src): 

		dist = [sys.maxint] * self.V 
		dist[src] = 0
		sptSet = [False] * self.V 

		for cout in range(self.V): 

			# Pick the minimum distance vertex from 
			# the set of vertices not yet processed. 
			# u is always equal to src in first iteration 
			u = self.minDistance(dist, sptSet) 

			# Put the minimum distance vertex in the 
			# shotest path tree 
			sptSet[u] = True

			# Update dist value of the adjacent vertices 
			# of the picked vertex only if the current 
			# distance is greater than new distance and 
			# the vertex in not in the shotest path tree 
			for v in range(self.V): 
				if self.graph[u][v] > 0 and sptSet[v] == False and	dist[v] > dist[u] + self.graph[u][v]: 
						dist[v] = dist[u] + self.graph[u][v] 

		sol = []
		for i in xrange(1, 8, 1):
			sol.append(dist[i*7-1])
		return sol


def xy2num(x, y):
	if x < 0 or x >= 7:
		return -1
	if y < y or y >= 7:
		return -1
	return y*7+x

r = remote("110.10.147.104", 15712)

r.sendlineafter(">> ", "G")
r.recvline()

ans = []

for i in xrange(100):
	r.recvline()
	smth = []
	for i in xrange(7):
		a = []
		b = r.recvline().rstrip().replace("  ", " ").split(' ')
		for i in b:
			if i != "":
				a.append(int(i))
		smth.append(a)

	# matrix to adjanceny
	# smth = [[99, 99, 99, 99, 99, 99, 99],
	# [99, 99, 99, 99, 99, 99, 99],
	# [99, 99, 99, 99, 99, 99, 99],
	# [99, 99, 99, 99, 99, 99, 99],
	# [99, 1, 1, 1, 99, 1, 1],
	# [1, 1, 99, 1, 99, 1, 99],
	# [99, 99, 99, 1, 1, 1, 99]]
	adj = []
	for y in xrange(7):
		for x in xrange(7):
			a = [0]*(7*7)
			
			if xy2num(x-1, y) >= 0:
				a[xy2num(x-1, y)] = smth[y][x-1]
			if xy2num(x+1, y) >= 0:
				a[xy2num(x+1, y)] = smth[y][x+1]
			if xy2num(x, y-1) >= 0:
				a[xy2num(x, y-1)] = smth[y-1][x]
			if xy2num(x, y+1) >= 0:
				a[xy2num(x, y+1)] = smth[y+1][x]

			adj.append(a)

	bestest = 1203981293812038102093890213890122839012839012830912803912809312809380912389012839018209380
	g = Graph(7*7)
	g.graph = adj
	for i in xrange(7):
		best = min(g.dtra(i*7))
		best += smth[i][0]
		bestest = min(bestest, best)

	r.sendlineafter(">>> ", str(bestest))
	ans.append(bestest)

r.close()
print "".join([chr(i) for i in ans]).decode("base64")
