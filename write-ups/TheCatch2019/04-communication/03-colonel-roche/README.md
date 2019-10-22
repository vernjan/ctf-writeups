# Colonel Roche (5p)
_Hi Commander,_

_did you know that the berserkers, which were assigned to specific tasks, have used to name
themselves after humans famous in given field of specialization (this behaviour is maybe
some bug in their firmware)? Our infiltrators - remotely operated classic devices equiped
with stickers `I'm smart` and `Death to humans` - have discovered a new Berserker named `Colonel
Roche`, which is responsible for encrypting the commands for the other less or more smart
devices. Your previous successes obviously forced the Berserkers to improve the security of
communication. You are supposed to find some way how to decrypt a captured message and read
the issued command(s). The infiltrators report that this particular machine usually uses a day
of week as a key (maybe `monday`, maybe `saturday`, maybe something else... they are not sure)._

_Good luck!_

[colonel_roche.encrypted](colonel_roche.encrypted)

---

This is the ciphertext:
```
463216327617246f67406f1266075ec622606c6671765537066636596e621e64e622c2b006066961c66e621f067676e77c6e665167a462c4b50477433617754222d7043542885747df6dd575970417d435223000
```

Let's do some analysis:
1) 84 bytes in hex, unlikely a block cipher, or with a small blocks
2) Divisors are `2 * 2 * 3 * 7` (and `* 2` if considering the original hex)
3) Frequency analysis
    ```
    Occurency and Frequency Analysis
    6	39×	23.21%
    7	22×	13.1%
    2	18×	10.71%
    4	14×	8.33%
    0	14×	8.33%
    5	12×	7.14%
    1	10×	5.95%
    3	9×	5.36%
    E	7×	4.17%
    C	6×	3.57%
    D	5×	2.98%
    F	4×	2.38%
    9	3×	1.79%
    B	2×	1.19%
    8	2×	1.19%
    A	1×	0.6%
    #N : 16	Σ = 168.00	Σ = 100.00
    ```

This looks like standard ASCII text (lots of 6s and 7s and also 2s and 0s which represents spaces).
Ok, this could be a [transposition cipher](https://en.wikipedia.org/wiki/Transposition_cipher#Columnar_transposition)
of hex encoded test!

Unlikely a running XOR cipher, the key would have to be non-ASCII.

There is also an obvious hint in the text to Google for `Colonel Roche`.
The hint points to [Jean-Baptiste Roche](https://fr.wikipedia.org/wiki/Jean-Baptiste_Roche). I was not sure
about the hint since I couldn't find anything useful about this person but the official hint confirms it:

_Full name of the mentioned famous human is `Colonel Jean-Baptiste Roche`, he lived in years 1861-1954 and his hobby was cryptography._

I Googled a lot to find something useful but I didn't find much so I settle for the fact that he lived
before the era of modern cryptography and that he was a Frenchman.

This strengthen my faith to go with the [transposition cipher](https://en.wikipedia.org/wiki/Transposition_cipher#Columnar_transposition).
The wiki says: _The system was regularly solved by the French .._
I tried a few online tools but none of them
worked so I took a deep dive and studied how the cipher works including it's various mutations. Then I
[programmed](../../../../src/main/kotlin/cz/vernjan/ctf/TranspositionCipher.kt) my own version of
transposition cipher. I tried all combinations of the weekdays, of course trying double transpositions
and brute-forcing all possible keys of reasonable length. However, I failed to decipher it ..

I got back to studying the ciphertext. I learnt that the it's most likely NOT a classic columnar transposition
cipher (read by columns) nor even double transposition cipher because the last ~60 chars are surely
a permutation of characters `FLAG{xxxx-xxxx-xxxx-xxxx}`. If this would be a classic transposition cipher,
the characters would be spread all over the ciphertext. This encouraged me once again to continue with
trying lots of possible permutations. I failed again, ran out of time and gave up :/