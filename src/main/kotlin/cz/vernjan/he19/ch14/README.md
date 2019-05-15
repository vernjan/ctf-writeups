# 14 - White Box
*Do you know the mighty **WhiteBox** encryption tool? Decrypt the following cipher text!*

```
9771a6a9aea773a93edc1b9e82b745030b770f8f992d0e45d7404f1d6533f9df348dbccd71034aff88afd188007df4a5c844969584b5ffd6ed2eb92aa419914e
```

[WhiteBox](WhiteBox)

---

Data start: 0x602060

Data start: 0x603060
Data end: 0x62b060
==> 163840 = 256 * 640 = 256 * 16 (block) * 4 (int) * 10 (rounds) WHY 10 ???

==> 167936 = 256 * 656 = 256 * 16 * 41

dd if=WhiteBox of=key.data bs=1 skip=8288 count=167936