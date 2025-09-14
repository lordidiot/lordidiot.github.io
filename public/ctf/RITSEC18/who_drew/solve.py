from Crypto.Cipher import AES

partial_key = "9aF738g9AkI112"

block = [""]*2
block[0] = "9e00000000000000000000000000436a".decode("hex") # 9exxxxxxxxxxxxxxxxxxxxxxxxxx436a
block[1] = "808e200a54806b0e94fb9633db9d67f0".decode("hex") # 808e200a54806b0e94fb9633db9d67f0
plain = [""]*2
plain[0] = "The message is protected by AES!"[:16]
plain[1] = "The message is protected by AES!"[16:]

def xor(a, b):
	return "".join([chr(ord(i)^ord(j)) for i, j in zip(a,b)])

def find_key():
	for i in xrange(256):
		for j in xrange(256):
			key = partial_key + chr(i) + chr(j)
			aes = AES.new(key, AES.MODE_ECB)
			d = aes.decrypt(block[1])
			if ord(d[0]) ^ ord(block[0][0]) == ord(plain[1][0]):
				if ord(d[-2]) ^ ord(block[0][-2]) == ord(plain[1][-2]):
					if ord(d[-1]) ^ ord(block[0][-1]) == ord(plain[1][-1]):
						return key
# find key
key = "9aF738g9AkI112#g" # key = find_key()	

# find block[0]
"""
block[1] = e( block[0] ^ plain[1] )
d( block[1] ) = block[0] ^ plain[1]
block[0] = d( block[1] ) ^ plain[1] 
"""
aes = AES.new(key, AES.MODE_ECB)
block[0] = xor( aes.decrypt(block[1]), plain[1] ) # 9e128e7bc9ab9cc9d8b13ec77389436a


# find iv
"""
block[0] = e( iv ^ plain[0] )
d( block[0] ) = iv ^ plain[0]
iv = d( block[0] ) ^ plain[0]
"""
iv = xor( aes.decrypt(block[0]), plain[0] )
print iv # FLAG
