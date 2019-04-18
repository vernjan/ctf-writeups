# 09 - rorriM rorriM
*Mirror, mirror, on the wall, who's the fairest of them all?*

[evihcra.piz](evihcra.piz)

---

I started with 
```
$ file evihcra.piz
TODO output
```

Unfortunately, this was a blind alley. I tried to open the camera RAW data using ThermalDataViewer and
ThermoVision but it took me nowhere.

Then I started to wonder why the name of the challenge is in reverse. Actually, if you reverse `evihcra.piz`
you get `archive.zip`. The trick is you also need to reverse the file content. I used this bash oneliner:

`< evihcra.piz xxd -p -c1 | tac | xxd -p -r > archive.zip`

Now we can unzip to get a new file `90gge.gnp`. The file's header is corrupted (`GNP` must be
changed to `PNG`). Fix the file extension and now we can finally open it:

![90gge.png](90gge.png)

Almost there, just invert the colors and flip vertically.

![egg09.png](egg09.png)



