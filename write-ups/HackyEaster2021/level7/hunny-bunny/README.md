# Hunny Bunny
hunnybunny loves music! Can you figure out what else he loves?

```
4ab56415e91e6d5172ee79d9810e30be5da8af18
c19a3ca5251db76b221048ca0a445fc39ba576a0
fdb2c9cd51459c2cc38c92af472f3275f8a6b393
6d586747083fb6b20e099ba962a3f5f457cbaddb
5587adf42a547b141071cedc7f0347955516ae13
```

⚑ format: `he2021{lowercaseonlynospaces}`

---

Hints are:
> - The values can be cracked, but they need to be changed somehow first.
> - One of the values represents the flag prefix.

Hints are very helpful in this case. Each line has exactly 40 chars (20 bytes). This matches
nicely SHA-1. Since we know the first line is `he2021{`, let's start there:
```
$ echo -n he2021{ | sha1sum
4de56415b91b6a5172bb79a9810b30eb5ad8dc18
```

Compare with the given value:
```
4de56415b91b6a5172bb79a9810b30eb5ad8dc18
4ab56415e91e6d5172ee79d9810e30be5da8af18
```

Digits are the same, letters are different. However, there is a simple pattern:
```
'a' -> 'd'
'b' -> 'e'
'c' -> 'f'
'd' -> 'a'
'e' -> 'b'
'f' -> 'c'
```

The first step is to fix the letters in the hashes:
```kotlin
fun main() {
    val encrypted = """
        4ab56415e91e6d5172ee79d9810e30be5da8af18
        c19a3ca5251db76b221048ca0a445fc39ba576a0
        fdb2c9cd51459c2cc38c92af472f3275f8a6b393
        6d586747083fb6b20e099ba962a3f5f457cbaddb
        5587adf42a547b141071cedc7f0347955516ae13
    """.trimIndent()

    encrypted.forEach { ch ->
        val new = when(ch) {
            'a' -> 'd'
            'b' -> 'e'
            'c' -> 'f'
            'd' -> 'a'
            'e' -> 'b'
            'f' -> 'c'
            else -> ch
        }
        print(new)
    }
}
```

It prints:
```
4de56415b91b6a5172bb79a9810b30eb5ad8dc18
f19d3fd5251ae76e221048fd0d445cf39ed576d0
cae2f9fa51459f2ff38f92dc472c3275c8d6e393
6a586747083ce6e20b099ed962d3c5c457fedaae
5587dac42d547e141071fbaf7c0347955516db13
```

I used https://hashtoolkit.com/decrypt-hash to reverse the hashes:
```
4de56415b91b6a5172bb79a9810b30eb5ad8dc18    he2021{
f19d3fd5251ae76e221048fd0d445cf39ed576d0    hunnybunny
cae2f9fa51459f2ff38f92dc472c3275c8d6e393    ilovemum
6a586747083ce6e20b099ed962d3c5c457fedaae    somuch
5587dac42d547e141071fbaf7c0347955516db13    !}
```

The flag is `he2021{hunnybunnyilovemumsomuch!}`