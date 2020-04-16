# 11 - Broken Egg

Uh-oh... The egg on this page has broken. Try to repair it!

![](broken_egg.png)

[broken_egg.zip](broken_egg.zip)

---

The archive contains `a.png` (corrupted image) and `b.png`:

![](b-corrupted.png)

The first step is to fix those corrupted images.

Fixing `a.png` is easy, there's a typo in the file header:
```
89 50 47 4E     .PGN
```
should be
```
89 50 4E 47     .PNG
```

Can be easily fixed with https://hexed.it/:

![](a-fixed.png)

Fixing `b.png` is also quite easy. Open the image in a hex editor, and you will notice
that there is Base64 encoded data appended to the end.

You can easily find where it starts by searching for `IEND`. The offset is `0x1CA4D` 
(`117325` in DEC).

Extract the data:
```
$ dd if=b.png bs=1 skip=117325 > b-b64.txt
$ cat b-b64.txt | base64 -d -i > b-fixed.png
```

And here is the second part of the image:

![](b-fixed.png)

Combine the two halves and get the egg:

![](solved.bmp)
