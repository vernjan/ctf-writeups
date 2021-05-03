# 46 Apes
46 apes encoded a message for you:

```
2Qu93ZhJHdsMGIlhmcgUXagMWe19icmBGbnFiOoBTZwIjM7FGd0gHdfNTbuB2a5V2X1JzcuF3MzNQf==
```

---

I ran into a nice rabbit hole here. Google took me on this page https://monkeysaudio.com/theory.html.
What a perfect fit! _Monkey Audio_ encoding, and the example uses 46!
Totally wrong..

Next I was pursuing the reverse - `sepa 64`. Sounded good. Not the right solution but it took me close.

The break through came when I tried to reverse the base encoded message (46 --> 64):
```
$ echo 2Qu93ZhJHdsMGIlhmcgUXagMWe19icmBGbnFiOoBTZwIjM7FGd0gHdfNTbuB2a5V2X1JzcuF3MzNQf | rev | base64 -d
}s3qns2u_eyk`nm3_tx4ta{220e0h:!gl`fr/uyc iu rhe c,tragnC
```

Not perfect, but the flag is here somehow...

After some time I realized, that some characters are just swapped. Then I finally understood the challenge:
```
4<-->6 a<-->p e<-->s = 64 pase --> 64 base
```

The characters in the base encoding are swapped. Decrypting is easy:
```kotlin
fun main() {
    val encrypted = "2Qu93ZhJHdsMGIlhmcgUXagMWe19icmBGbnFiOoBTZwIjM7FGd0gHdfNTbuB2a5V2X1JzcuF3MzNQf=="
    val decrypted = arrayOfNulls<Char>(encrypted.length)

    encrypted.forEachIndexed { index, _ ->
        if (index % 2 == 0) {
            decrypted[index] = encrypted[index + 1]
            decrypted[index + 1] = encrypted[index]
        }
    }

    println(decrypted.joinToString("").decodeBase64())
}
```

Outputs: `Congrats, here is your flag: he2021{th4ts_m0nkey_bus1n3ss}`

The flag is `he2021{th4ts_m0nkey_bus1n3ss}`