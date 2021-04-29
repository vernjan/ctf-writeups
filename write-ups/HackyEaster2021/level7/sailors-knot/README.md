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
is about [ROP - Return-oriented programming](https://en.wikipedia.org/wiki/Return-oriented_programming):
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


https://docs.pwntools.com/en/latest/intro.html


# TODO - Read https://www.ret2rop.com/ and write down a quick cheat sheet!

https://libc.blukat.me/