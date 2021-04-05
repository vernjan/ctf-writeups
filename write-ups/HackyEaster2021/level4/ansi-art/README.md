# Ansi Art
Hope you like my ansi art egg!

Get it with `nc 46.101.107.117 2105`

---

Let's run the command!

![](ansi-egg.png)

Okay, this is how it looks in text view:
```
[38;5;16;48;5;16m▓[38;5;16;48;5;16m▓[38;5;16;48;5;16m▓[38;5;16;48;5;16m▓ ...
```

Lot's of [ANSI Escape sequences](https://en.wikipedia.org/wiki/ANSI_escape_code).

Searching through the file, I have found the flag:
```
[30mh[31me[32m2[33m0[34m2[35m1[36m{[37m4[90mN[91ms[92m1[93mM[94mG[95m1[96mk[97m}
```

It just needs a bit of cleaning up.
I deleted the escape sequences by a simple regex pattern `\[.{2}m`.

The flag is `he2021{4Ns1MG1k}`