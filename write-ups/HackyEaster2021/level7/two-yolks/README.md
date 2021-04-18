# Two Yolks
This egg has two yolks.

But the second seems to be hidden somehow.

[twoyolks.png](twoyolks.png)

---

I was unable to open the image with _Stegsolve_ so I ran [pngcheck](http://www.libpng.org/pub/png/apps/pngcheck.html):
```
$ pngcheck twoyolks.png
twoyolks.png  illegal (unless recently approved) unknown, public chunk YHDR
ERROR: twoyolks.png
```

This is clearly wrong, correct chunk name is `IHDR`. I fixed it in https://hexed.it/ and run _pngcheck_ again:
```
$ pngcheck twoyolks2.png
twoyolks2.png  multiple IHDR not allowed
ERROR: twoyolks2.png
```

I completely removed the first `IHDR` chunk (from `0xC` to `0x3705`) and re-ran _pngcheck_:
```
$ pngcheck twoyolks3.png
twoyolks3.png  illegal (unless recently approved) unknown, public chunk YDAT
ERROR: twoyolks3.png
```

This was the last issue. Now you can read the image:
![](egg.png)

The flag is `he2021{tw0_y0lks_are_gre33eat}`