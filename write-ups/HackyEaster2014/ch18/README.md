# 18 - Paper and Pen

Crack the following ciphertext, in order to get the password for the egg-o-matic. Hint: lowercase letters only.

```
Dii2 Dii3 Di2 Gi1 Gi1 Aiii1 Diii2 Gi3 Aiii2 Gi2 Giii1 Dii3 Aiii3 Gii3 Di2 Diii3
```

---

As the challenge title suggests, this is more of a classic cipher. I noticed that we can
easily group elements by three:
- `A`, `D`, `G`
- `i`, `ii`, `iii`
- `1`, `2`, `3`

`3^3 = 27` which is a good fit for alphabet. Also, the hint is _lowercase letters only_.

So far so good. My first thought was to convert to _ternary numeral system_, but it
didn't work. I got stuck then. I was close but yet unable to get the password.

The correct solution was to apply [Trifid cipher](https://en.wikipedia.org/wiki/Trifid_cipher).

Since I already had programmed the ternary converter, I made one simple change and finally got
the password:
```kotlin
// return firstDigit * 9 + secondDigit * 3 + thirdDigit // Nope
return secondDigit * 9 + firstDigit * 3 + thirdDigit
```

See [PaperAndPen.kt](../../../src/main/kotlin/cz/vernjan/ctf/he14/ch18/PaperAndPen.kt)

The password is `noeggswithyourex`