package cz.vernjan.ctf.hv20

import java.lang.AssertionError

fun main() {
    val dna1 =
        "CTGTCGCGAGCGGATACATTCAAACAATCCTGGGTACAAAGAATAAAACCTGGGCAATAATTCACCCAAACAAGGAAAGTAGCGAAAAAGTTCCAGAGGCCAAA"

    val dna2 =
        "ATATATAAACCAGTTAATCAATATCTCTATATGCTTATATGTCTCGTCCGTCTACGCACCTAATATAACGTCCATGCGTCACCCCTAGACTAATTACCTCATTC"

    val flag = dnaToBinary(dna1).zip(dnaToBinary(dna2))
        .joinToString("") {
            if (it.first == it.second) "0" else "1" // XOR
        }
        .chunked(8)
        .map { Integer.parseInt(it, 2) }
        .map { it.toChar() }
        .joinToString("")

    println(flag)
}

private fun dnaToBinary(dna: String) = dna.map {
    when (it) {
        'A' -> "00"
        'C' -> "01"
        'T' -> "11"
        'G' -> "10"
        else -> throw AssertionError()
    }
}.joinToString("")
