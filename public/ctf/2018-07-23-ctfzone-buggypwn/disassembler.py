from struct import unpack

def u(a):
	return unpack("<I", a)[0]

def getDWORD(a):
	if len(a) <= 4:
		print "ERROR LESS THAN 4 BYTES TO READ FROM"
		return
	real_dword = u(''.join([chr(i[0]) for i in a[0:4]]))
	imag_dword = u(''.join([chr(i[1]) for i in a[0:4]]))
	return (real_dword, imag_dword)

call_stack = []

def parse(instr, addr):
	global call_stack
	commands={
			 0x00:  "__command_powerdown",
			 
			 0x20:  "__command_nop",
			 0x30:  "__command_add",
			 0x31:  "__command_mov_data",
			 0x32:  "__command_xor",
			 0x33:  "__command_rotip",
			 0x40:  "__command_test",
			 0x41:  "__command_mov_reg",
			 0x42:  "__command_mov_data_to_reg",
			 0x43:  "__command_mov_data_from_reg",
			 0x45:  "__command_call",
			 0x46:  "__command_ret",
			 0x47:  "__command_jmpne",
			 0x48:  "__command_sub",
			 0x49:  "__command_syscall",
			 0x50:  "__command_switch",}

	dataregs=["eax", "ebx", "ecx", "edx", "esi", "edi", "edid", "esp"]
	amplifier = instr[0][1]

	if instr[0][0] not in commands:
		return (addr+1, "--")

	#CALL
	if commands[instr[0][0]] == "__command_call":
		real_addr = getDWORD(instr[1:])[0]
		imag_addr = getDWORD(instr[1:])[1]
		call_stack.append(addr+5)
		return (real_addr, "call 0x{:08x}, 0x{:08x}".format(real_addr, imag_addr))
	#MOV
	elif commands[instr[0][0]] == "__command_mov_data":
		inreg=amplifier&0xf
		tp=amplifier>>4
		return (addr+5, "mov {}, (0x{:08x}, 0x{:08x}) | tp = {}".format(dataregs[inreg], getDWORD(instr[1:])[0], getDWORD(instr[1:])[1], tp))
	#SYSCALL
	elif commands[instr[0][0]] == "__command_syscall":
		if amplifier==1:
			return (addr+1, "syscall_print : eax")
		elif amplifier==2:
			return (addr+1, "syscall_write : [edi] --> edid, edx bytes (no bad chars)")
		elif amplifier==3:
			return (addr+1, "syscall_print : [edi] --> edid, edx bytes")
		elif amplifier==4:
			return (addr+1, "im not sure, write some random stuff to stack(?)")
		elif amplifier==5:
			return (addr+1, "ecx = (atoi(user_input), 0)")
		elif amplifier==0x40:
			return (addr+1, "eax == ('f', 'l') && ebx == ('a','g') >>>> FLAG!!!!")
		else:
			print "bad syscall!"
	#MOV REG
	elif commands[instr[0][0]] == "__command_mov_reg":
		inreg=amplifier&0xf
		outreg=amplifier>>4
		return (addr+1, "mov {}, {}".format(dataregs[inreg], dataregs[outreg]))
	#ADD REG
	elif commands[instr[0][0]] == "__command_add":
		inreg=amplifier&0xf
		outreg=amplifier>>4
		return (addr+1, "add {}, {}".format(dataregs[inreg], dataregs[outreg]))
	#SUB REG
	elif commands[instr[0][0]] == "__command_sub":
		inreg=amplifier&0xf
		sub = getDWORD(instr[1:])
		return (addr+5, "mov tmp, 0x{:08x}, 0x{:08x} | sub esp, tmp".format(sub[0], sub[1]))

	#XOR REG
	elif commands[instr[0][0]] == "__command_add":
		inreg=amplifier&0xf
		outreg=amplifier>>4
		return (addr+1, "xor {}, {}".format(dataregs[inreg], dataregs[outreg]))
	#JNE
	elif commands[instr[0][0]] == "__command_jmpne":
		jmp_addr = getDWORD(instr[1:])
		print "if ecx.real > 1; jmp 0x{:08x}, 0x{:08x}, take jump? (y/n)".format(jmp_addr[0], jmp_addr[1])
		if raw_input() == 'y':
			return (jmp_addr[0], "took jump to 0x{:08x}, 0x{:08x}".format(jmp_addr[0], jmp_addr[1]))
		else:
			return (addr+5, "didnt jump") 
	#RET
	elif commands[instr[0][0]] == "__command_ret":
		ret = call_stack[-1]
		call_stack = call_stack[:-1]
		return (ret, "ret")
	#POWERDOWN
	elif commands[instr[0][0]] == "__command_powerdown":
		return (addr, "POWERDOWN")
		

	else:
		print "Havent wrote parsing for {}!".format(commands[instr[0][0]])
		return (addr+1, "-")


def disass(_text):
	eip = 0x60000
	base = 0x60000
	while (eip-base) < len(_text):
		parsed = parse(_text[eip-base:], eip)
		old_eip = eip
		eip = parsed[0] #new addr
		#print "________________________________"
		print "0x{:08x}| {}".format(old_eip, parsed[1]) #disassembled
		print ""
		if parsed[1] == "POWERDOWN":
			break


code = "\x45\x00\x06\x00\x00\x00\x06\x06\x00\x00"
code +=	"\x00\x00"
code += "\x31\x05\x40\x40\x00\x00\x06\x06\x00\x00"
code +="\x31\x03\x04\x00\x00\x00\x00\x00\x00\x00"
code +="\x31\x06\x01\x00\x00\x00\x00\x00\x00\x00"
code +="\x49\x03"

code +="\x31\x05\x40\x41\x00\x00\x06\x06\x00\x00"
code +="\x31\x03\x09\x00\x00\x00\x00\x00\x00\x00"
code +="\x49\x03"
code +="\x31\x04\x40\x45\x00\x00\x06\x06\x00\x00"
code +="\x31\x01\x00\x01\x00\x00\x00\x00\x00\x00"
code +="\x49\x05"
			
code +="\x31\x05\x40\x42\x00\x00\x06\x06\x00\x00"
code +="\x31\x03\x09\x00\x00\x00\x00\x00\x00\x00"
code +="\x49\x03"

code +="\x41\x45"
code +="\x31\x03\x10\x00\x00\x00\x00\x00\x00\x00"
code +="\x49\x02"
code +="\x30\x14"
code +="\x47\x00\x2c\x00\x00\x00\x06\x06\x00\x00"

code +="\x31\x05\x40\x43\x00\x00\x06\x06\x00\x00"
code +="\x31\x03\x09\x00\x00\x00\x00\x00\x00\x00"
code +="\x49\x03"

code +="\x49\x05"

code +="\x31\x05\x40\x44\x00\x00\x06\x06\x00\x00"
code +="\x31\x03\x10\x00\x00\x00\x00\x00\x00\x00"
code +="\x49\x03"

code +="\x48\x07\x10\x00\x00\x00\x00\x00\x00\x00"
code +="\x41\x75"
code +="\x41\x23"
code +="\x49\x02"
code +="\x49\x03"
code +="\x48\x07\xf0\x00\xff\x00\xff\x00\xff\x00"
code +="\x46\x00"

code = [(ord(code[i]), ord(code[i+1])) for i in xrange(0, len(code), 2)]


disass(code)