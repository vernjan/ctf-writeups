# 09 - rorriM rorriM
*Mirror, mirror, on the wall, who's the fairest of them all?*

[evihcra.piz](evihcra.piz)

---

I started with 
```
$ file evihcra.piz
evihcra.piz: DIY-Thermocam raw data (Lepton 3.x), scale 24575-64617, spot sensor temperature 0.000000, color scheme 163, minimum point enabled, maximum point enabled, calibration: offset -0.000000, slope 6523.970215
```

Unfortunately, this was a blind alley. I tried to open the camera RAW data using
[ThermalDataViewer](https://github.com/maxritter/DIY-Thermocam/tree/master/Software/Thermal%20Data%20Viewer) and
[ThermoVision](https://github.com/maxritter/DIY-Thermocam/tree/master/Software/Thermal%20Analysis%20Software)
but it took me nowhere.

So back to beginning..

I started to wonder why the name of the challenge is in reverse. Actually, if you reverse `evihcra.piz`
you get `archive.zip`. The trick is you also need to reverse the file content. I used this bash oneliner:

`< evihcra.piz xxd -p -c1 | tac | xxd -p -r > archive.zip`

Now we can unzip to get a new file `90gge.gnp`. The file's header is corrupted (`GNP` must be
changed to `PNG`). Fix the file extension and now we can finally open it:

![90gge.png](90gge.png)

Almost there, just invert the colors and flip vertically.

![egg09.png](egg09.png)



