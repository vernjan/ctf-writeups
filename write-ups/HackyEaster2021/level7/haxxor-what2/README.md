# Haxxor what 2?
I was able to break the first file, but I'm stuck at this one.

Help!

[haxxorwhat2](haxxorwhat2)

---

Viewing the file in a text editor, I noticed repeating patterns such as `anx` or `xor`.
This is the leaking _xor_ key. 

```
$ head -c 100 haxxorwhat2 |xxd
00000000: 2824 7168 7574 616e 706f 67f4 b024 25fe  ($qhutanpog..$%.
00000010: 6244 5126 6174 7b3e 786f 756c 7d74 0409  bDQ&at{>xoul}t..
00000020: 1f41 0202 0621 3567 786c 4b20 8b2a f856  .A...!5gxlK .*.V
00000030: 9331 0714 6a74 606a 8d6e 726c 6560 616e  .1..jt`j.nrle`an
00000040: 7832 c815 3df8 8c99 7f11 9c17 971d fa98  x2..=...........
00000050: 11bc d6be cbd2 2c65 9201 fd3a 450d 25ed  ......,e...:E.%.
00000060: 2ce7 e041                                ,..A

$ tail -c 100 haxxorwhat2 |xxd
00000000: 5331 3f60 6c66 6c66 6c61 7469 6e6d f7a3  S1?`lflflatinm..
00000010: 3c25 e47b 455b 2572 6c7b 2461 6e7f 6f6a  <%.{E[%rl{$an.oj
00000020: 6c61 7461 6e78 6f72 6cc5 f561 6e78 6f17  latanxorl..anxo.
00000030: 0b06 5a11 001f 3a26 6961 7758 2292 3107  ..Z...:&iawX".1.
00000040: 146a 7460 6a8d 6e72 6c65 6061 6e78 3f39  .jt`j.nrle`anx?9
00000050: 6967 7461 6e78 6e72 6d61 3961 6e78 0b38  igtanxnrma9anx.8
00000060: 6c61 7461                                lata
```

It's quite easy to guess the key. I tried a few combinations using https://gchq.github.io/CyberChef.
Once I started the key with `xor`, it became obvious this is an encrypted zip file (magic header starts with `PK`). 
It's also obvious the key is: `xorlatan`.

Having the key, we can decrypt the file (I used _CyberChef_), unzip [it](haxxorwhat2.zip) and grab the egg:

![](egg.png)

The flag is `he2021{ul1m4te_x0r_m4st3r}`