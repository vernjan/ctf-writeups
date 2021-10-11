# The Dark Side

Hi Expert,

the archaeologists believe that domain `thecatchu6jlyqgen3ox74kjcfr5lmwdc7jqj3vmekq6y45dmvo5xmad.onion` could contain interesting information intended for dark minded. Check it out.

Good Luck!

---

The first step is to visit the URL using [Tor browser](https://www.torproject.org/download/).
Download the base64 encoded [data](../../../../src/main/resources/cz/vernjan/ctf/catch21/DarkSide-data.txt).
Then, iteratively decode the data while collecting the first letters separated with `;`:
```kotlin
import cz.vernjan.ctf.Resources
import cz.vernjan.ctf.decodeBase64

fun main() {
    var data = Resources.asString("catch21/DarkSide-data.txt").decodeBase64()

    while (data.contains(";")) {
        val (message, tail) = data.split(";")
        print(message)
        data = tail.decodeBase64()
    }
}
```

It prints out: `Here you are: FLAG{uNMI-DKSU-NKmq-7QE0}.`