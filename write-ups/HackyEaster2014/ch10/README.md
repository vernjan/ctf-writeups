# 10 - Hidden Egg

_In case you are interested, here's the flyer of the 2014 competition._

[Hacky_Easter_Flyer.pdf](Hacky_Easter_Flyer.pdf)

---

Extract all JPEGs from the PDF:
```
$ binwalk --dd='jpeg:jpg' Hacky_Easter_Flyer.pdf

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PDF document, version: "1.5"
597           0x255           Zlib compressed data, default compression
1370          0x55A           JPEG image data, JFIF standard 1.01
1400          0x578           TIFF image data, big-endian, offset of first image directory: 8
48247         0xBC77          Zlib compressed data, default compression
49973         0xC335          JPEG image data, JFIF standard 1.01
50003         0xC353          TIFF image data, big-endian, offset of first image directory: 8
81055         0x13C9F         JPEG image data, JFIF standard 1.01
81085         0x13CBD         TIFF image data, big-endian, offset of first image directory: 8
141054        0x226FE         Zlib compressed data, default compression
142108        0x22B1C         Zlib compressed data, default compression
142570        0x22CEA         Zlib compressed data, default compression
155747        0x26063         Zlib compressed data, default compression
156118        0x261D6         Zlib compressed data, default compression
165030        0x284A6         Zlib compressed data, default compression
186145        0x2D721         Zlib compressed data, default compression
186471        0x2D867         Zlib compressed data, default compression
199013        0x30965         Zlib compressed data, default compression
```

`C335.jpg` is the one:

![](C335.jpg)
