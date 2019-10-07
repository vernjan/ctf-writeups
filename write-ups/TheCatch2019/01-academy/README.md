# The Academy
_Hi Cadet, this is just mental warm-up, do not expect any medals! Decode the message, go go go!_

---

## 01 - Twosome (1p)
```shell script
$ gunzip message.bin.gz 
$ cat message.bin
1000110 1001100 1000001 1000111 1111011 1110010 1111010 1110111 1100001 101101 1110000 110010 1010000 1111001 101101 111001 110110 1010010 1111001 101101 1000110 1100100 1011010 1010101 1111101
```

https://onlineasciitools.com/convert-binary-to-ascii

`FLAG{rzwa-p2Py-96Ry-FdZU}`

## 02 - Octopus (1p)
```shell script
$ gunzip message.oct.gz 
$ cat message.oct
106 114 101 107 173 172 125 113 171 55 65 161 156 112 55 160 67 114 104 55 63 146 151 164 175
```

https://onlineasciitools.com/convert-octal-to-ascii

`FLAG{zUKy-5qnJ-p7LD-3fit}`

## 03 - Foxtrot is the maximum (1p)

```shell script
$ gunzip message.hex.gz 
$ cat message.hex
46 4c 41 47 7b 38 4d 56 58 2d 4c 68 38 6d 2d 74 4d 4d 49 2d 4b 38 73 69 7d
$ cat message.hex | xxd -r -p
FLAG{8MVX-Lh8m-tMMI-K8si}
```

## 04 - Textual data (1p)
```shell script
$ gunzip message.b64.gz 
$ cat message.b64
RkxBR3tTNXJyLXJDeHQtYW1ZWS03WDQ2fQ==
$ cat message.b64 | base64 -D
FLAG{S5rr-rCxt-amYY-7X46}
```