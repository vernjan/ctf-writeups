# 06 - E(gg)-Mail

A friend of yours sniffed some E-Mail communication, and extracted a message for you. Inspect the file he provided, in order to find an easter egg.

![](egg_mail.jpg)

[egg_mail.txt](egg_mail.txt)

---

Decode from Base64 and extract all PNGs:
```
$ cat egg_mail.txt | tr -d '\n' | base64 -d > egg_mail.bin
$ binwalk -D 'png image:png' egg_mail.bin 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
14336         0x3800          PNG image, 480 x 480, 8-bit/color RGB, non-interlaced
14377         0x3829          Zlib compressed data, compressed
$ xdg-open _egg_mail.bin.extracted/3800.png
```

![](_egg_mail.bin.extracted/3800.png)