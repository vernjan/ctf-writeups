# HV19.22 The command ... is lost

_Santa bought this gadget when it was released in 2010. He did his own DYI project to control his
sledge by serial communication over IR. Unfortunately Santa lost the source code for it and doesn't
remember the command needed to send to the sledge. The only thing left is this file:
[thecommand7.data](thecommand7.data)_

_Santa likes to start a new DYI project with more commands in January, but first he needs
to know the old command. So, now it's on you to help out Santa._

---

https://en.wikipedia.org/wiki/ATmega328

https://electronics.stackexchange.com/questions/16670/avr-disassembler-with-named-register-support

https://github.com/twinearthsoftware/AVRDisassembler

avr-objdump -s -m avr5 thecommand7.hex > thecommand7.dump


avr-objdump -d -j .sec1 -m avr5 thecommand7.hex

https://github.com/twinearthsoftware/AVRDisassembler


089E:	30-31       	cpi r19, 0x10   
08A0:	33-39       	cpi r19, 0x93   
08A2:	48-53       	subi r20, 0x38  
08A4:	56-5F       	subi r21, 0xf6  
08A6:	61-63       	ori r22, 0x31   
08A8:	64-67       	ori r22, 0x74   
08AA:	68-6C       	ori r22, 0xc8   
08AC:	6D-6E       	ori r22, 0xed   
08AE:	72-74       	andi r23, 0x42  
08B0:	78-79       	andi r23, 0x98  
08B2:	7B-7D       	andi r23, 0xdb  

:1008 9E00 30 31 33 39 48 53 56 5F 61 63 64 67 6 8 6C 6D 6E EF
:1008 AE00 72 74 78 79 7B 7D 00 2020202020202020204B

089E: 01
08A0: 39
08A2: HS
08A4: V_
08A6: ac
08A8: dg
08AA: hl
08AC: mn
08AE: rt
08B0: xy
08B2: {}


HV19{S...}
HV19{Santa_...}

x, x+2, x-3, x-1, x18.. 

HV19{H3y_Sl3dg3_m33t_m3_at_th3_n3xt_c0rn3r}

0x0117  0x0104  H
0x0118  0x0106  V
0x0119  0x0101  1
0x011a  0x0103  9
0x011b  0x0114  {
0x011c  0x0104  H
0x011d  0x0102  3
0x011e  0x0113  y
0x011f  0x0107  _
0x0120  0x0105  S
0x0121  0x010d  l
0x0122  0x0102  3
0x0123  0x010a  d
0x0124  0x010b  g
0x0125  0x0102  3
0x0126  0x0107  _
0x0127  0x010e  m 
0x0128  0x0102  3
0x0129  0x0102  3
0x012a  0x0111  t
0x012b  0x0107  _
0x012c  0x010e  m
0x012d  0x0102  3
0x012e  0x0107  _
0x012f  0x0108  a
0x0130  0x0111  t
0x0131  0x0107  _
0x0132  0x0111  t
0x0133  0x010c  h
0x0134  0x0102  3
0x0135  0x0107  _
0x0136  0x010f  n
0x0137  0x0102  3
0x0138  0x0112  x
0x0139  0x0111  t
0x013a  0x0107  _
0x013b  0x0109  c
0x013c  0x0100  0
0x013d  0x0110  r
0x013e  0x010f  n
0x013f  0x0102  3
0x0140  0x0110  r
0x0141  0x0115  }