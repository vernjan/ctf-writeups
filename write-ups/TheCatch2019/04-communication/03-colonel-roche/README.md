# Colonel Roche (5p)
_Hi Commander,_

_did you know that the berserkers, which were assigned to specific tasks, have used to name
themselves after humans famous in given field of specialization (this behaviour is maybe
some bug in their firmware)? Our infiltrators - remotely operated classic devices equiped
with stickers `I'm smart` and `Death to humans` - have discovered a new Berserker named `Colonel
Roche`, which is responsible for encrypting the commands for the other less or more smart
devices. Your previous successes obviously forced the Berserkers to improve the security of
communication. You are supposed to find some way how to decrypt a captured message and read
the issued command(s). The infiltrators report that this particular machine usually uses a day
of week as a key (maybe `monday`, maybe `saturday`, maybe something else... they are not sure)._

_Good luck!_

[colonel_roche.encrypted](colonel_roche.encrypted)

---

84 bytes (672 bits) ? IV?
84 = 3 * 7 * 2 * 2
```
463216327617246f67406f1266075ec622606c6671765537066636596e621e64e622c2b006066961c66e621f067676e77c6e665167a462c4b50477433617754222d7043542885747df6dd575970417d435223000

46 32 16 32 76 17 24 6f 67 40 6f 12 66 07 5e c6 22 60 6c 66 71 76 55 37 06 66 36 59 6e 62 1e 64 e6 22 c2 b0 06 06 69 61 c6 6e 62 1f 06 76 76 e7 7c 6e 66 51 67 a4 62 c4 b5 04 77 43 36 17 75 42 22 d7 04 35 42 88 57 47 df 6d d5 75 97 04 17 d4 35 22 30 00

70 50 22 50 118 23 36 111 103 64 111 18 102 7 94 198 34 96 108 102 113 118 85 55 6 102 54 89 110 98 30 100 230 34 194 176 6 6 105 97 198 110 98 31 6 118 118 231 124 110 102 81 103 164 98 196 181 4 119 67 54 23 117 66 34 215 4 53 66 136 87 71 223 109 213 117 151 4 23 212 53 34 48 0
```

```
46 32 16 32 76 17 24 6f 67 40 6f 12 66 07 5e c6
22 60 6c 66 71 76 55 37 06 66 36 59 6e 62 1e 64 
e6 22 c2 b0 06 06 69 61 c6 6e 62 1f 06 76 76 e7 
7c 6e 66 51 67 a4 62 c4 b5 04 77 43 36 17 75 42 
22 d7 04 35 42 88 57 47 df 6d d5 75 97 04 17 d4 
35 22 30 00
```

https://link.springer.com/chapter/10.1007/978-3-642-31284-7_19

Frequency bytes:
56 unique bytes (out of 84)
```
06	4×	4.76%
22	4×	4.76%
66	4×	4.76%
76	4×	4.76%
62	3×	3.57%
04	3×	3.57%
17	3×	3.57%
```

C6, C4, D7, B5, D7, DF, D5, D4, A4, C2,