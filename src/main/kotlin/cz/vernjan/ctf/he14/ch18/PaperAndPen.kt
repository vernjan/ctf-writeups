package cz.vernjan.ctf.he14.ch18

import java.lang.AssertionError

fun main() {

    val cipherText = "Dii2 Dii3 Di2 Gi1 Gi1 Aiii1 Diii2 Gi3 Aiii2 Gi2 Giii1 Dii3 Aiii3 Gii3 Di2 Diii3"

    val decrypted = cipherText
        .split(" ")
        .map { toNumber(it) + 'a'.toInt() }
        .map { it.toChar() }
        .joinToString("")

    println(decrypted)
}

fun toNumber(chunk: String): Int {
    val firstDigit: Int = when (chunk.first()) {
        'A' -> 0
        'D' -> 1
        'G' -> 2
        else -> throw AssertionError()
    }
    val secondDigit: Int = chunk.substring(1, chunk.length - 1).count() - 1
    val thirdDigit: Int = Integer.parseInt(chunk.last().toString()) - 1
    return secondDigit * 9 + firstDigit * 3 + thirdDigit
}