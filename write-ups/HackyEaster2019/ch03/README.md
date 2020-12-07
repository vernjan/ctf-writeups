# 03 - Sloppy Encryption

*The easterbunny is not advanced at doing math and also really sloppy.*

*He lost the encryption script while hiding your challenge. Can you decrypt it?*

`K7sAYzGlYx0kZyXIIPrXxK22DkU4Q+rTGfUk9i9vA60C/ZcQOSWNfJLTu4RpIBy/27yK5CBW+UrBhm0=`

[sloppy.rb](sloppy.rb)

---

I started with analyzing `sloppy.rb`. This [Ruby online REPL](https://repl.it/languages/ruby) helped me a lot.
I added a few debugging prints and learnt how the encryption works. Then I wrote a simple Kotlin program for decryption. 

```kotlin
private val KEY = BigInteger("5".repeat(101))

fun cz.vernjan.ctf.hv20.cz.vernjan.ctf.hv20.cz.vernjan.ctf.hv20.main() {
    val encrypted = "K7sAYzGlYx0kZyXIIPrXxK22DkU4Q+rTGfUk9i9vA60C/ZcQOSWNfJLTu4RpIBy/27yK5CBW+UrBhm0="
    val decoded: ByteArray = Base64.getDecoder().decode(encrypted)
    val decrypted: BigInteger = BigInteger(decoded).divide(KEY)
    println(decrypted.toString(16).hexToAscii())
}
```

Full source code [here](../../../src/main/kotlin/cz/vernjan/ctf/he19/ch03/Challenge03.kt).

And the password is `n00b_style_crypto`