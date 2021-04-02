# Mystical Symbols
I found these mystical symbols.

What do they mean?

[symbols.png](symbols.png)

---

Finally, (and **I hope I will not make the same mistake** with easy challenges) I wasted time on this one because I was
refusing to use the official hint.

I made lots of observations about the patterns, and I was trying to decipher them by hand.

Wrong! Use Google (and the hints) next time!

The hints were:
> - Really **myst**ical, isn't it?
> - decimal to ascii

Googling for `myst symbols` pointed me to https://dni.fandom.com/wiki/D%27ni_Numerals.

Now it really is easy. Decode the symbols as:
```
3*25+8  = 83    (S)
1*25+24 = 49    (1)
4*25+14 = 114   (r)
4*25+14 = 114   (r)
4*25+17 = 117   (u)
4*25+22 = 122   (z)
```

The flag is `he2021{S1rruz}`