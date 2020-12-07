# HV20.05 Image DNA

_Santa has thousands of Christmas balls in stock. They all look the same, but he can still tell them apart. Can you see the difference?_

![](ball1.jpg) ![](ball2.jpg)

---

At first, I tried to combine the images using _Stegsolve_, but it took me nowhere.

Next, I opened the images with hex editor and noticed that there is some extra stuff:

- In `ball1.jpg` at the very end (after JPG's end marker `FF D9`):
  ```
  CTGTCGCGAGCGGATACATTCAAACAATCCTGGGTACAAAGAATAAAACCTGGGCAATAATTCACCCAAACAAGGAAAGTAGCGAAAAAGTTCCAGAGGCCAAA
  ```

- Similarly, in `ball2.jpg`:
  ```
  ATATATAAACCAGTTAATCAATATCTCTATATGCTTATATGTCTCGTCCGTCTACGCACCTAATATAACGTCCATGCGTCACCCCTAGACTAATTACCTCATTC
  ```

- Hidden ZIP archive: `hidden.zip`. The archive contains a single file named `A` containing short string `00`.

Back to those suspicious `CTGTCGCG..` strings. Googling a bit, I realized it's a DNA sequence
(also the name of the challenge is _Image DNA_).

The obvious solution was to combine both DNA sequences based on the biological rules:
`A + T` and `C + G`. Unfortunately, this wasn't the right solution.

Being a bit desperate, I googled for `ATCG 00` and I was pointed to
[Decoding DNA sequence into binary](https://www.mathworks.com/matlabcentral/answers/244696-decoding-dna-sequence-into-binary).

Of course, I need to first **encode those DNA sequences into binary**!

I was not sure how to do it since I only knew that `AA=0` but there is really not that
many options. I applied some guess work:
- Solution is 208 bits (2x104), that makes 26 chars in ASCII
- The first bit can't be `1` (because of basic ASCII range)
- DNA sequences start with `A` (`00`) and `C` so `C` must be `01`

Only 2 options left for `T` an `A`. Here is the program to decode the flag:
```kotlin
fun cz.vernjan.ctf.hv20.cz.vernjan.ctf.hv20.cz.vernjan.ctf.hv20.main() {
    val dna1 =
        "CTGTCGCGAGCGGATACATTCAAACAATCCTGGGTACAAAGAATAAAACCTGGGCAATAATTCACCCAAACAAGGAAAGTAGCGAAAAAGTTCCAGAGGCCAAA"

    val dna2 =
        "ATATATAAACCAGTTAATCAATATCTCTATATGCTTATATGTCTCGTCCGTCTACGCACCTAATATAACGTCCATGCGTCACCCCTAGACTAATTACCTCATTC"

    val flag = cz.vernjan.ctf.hv20.dnaToBinary(dna1).zip(cz.vernjan.ctf.hv20.dnaToBinary(dna2))
        .joinToString("") {
            if (it.first == it.second) "0" else "1" // XOR
        }
        .chunked(8)
        .map { Integer.parseInt(it, 2) }
        .map { it.toChar() }
        .joinToString("")

    println(flag)
}

private fun cz.vernjan.ctf.hv20.dnaToBinary(dna: String) = dna.map {
    when (it) {
        'A' -> "00"
        'C' -> "01"
        'T' -> "11"
        'G' -> "10"
        else -> throw AssertionError()
    }
}.joinToString("")
```

The flag is `HV20{s4m3s4m3bu7diff3r3nt}`
