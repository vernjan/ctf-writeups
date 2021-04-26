package cz.vernjan.ctf

import org.apache.commons.codec.binary.Hex
import java.util.*

private val base64Decoder = Base64.getDecoder()
private val base64Encoder = Base64.getEncoder()

fun String.hexToByteArray(): ByteArray = Hex.decodeHex(this)
fun ByteArray.toHex(): String = Hex.encodeHexString(this)

fun String.hexToAscii(): String = String(hexToByteArray())
fun String.asciiToHex(): String = Hex.encodeHexString(toByteArray())

fun String.decodeBase64(): String = String(base64Decoder.decode(this))
fun String.encodeBase64(): String = base64Encoder.encodeToString(this.toByteArray())

fun String.hexToBase64(): String = base64Encoder.encodeToString(this.hexToByteArray())
fun String.base64ToHex(): String = base64Decoder.decode(this).toHex()

fun String.decodeBaseUrl64(): String = String(Base64.getUrlDecoder().decode(this))

fun Int.toHex(): String = Integer.toHexString(this)
fun String.hexToInt(): Int = Integer.parseInt(this, 16)

@ExperimentalUnsignedTypes
fun Byte.toBinary(): String = this.toUByte().toString(2).padStart(8, '0')

fun String.rot13(): String = this
        .map {
            if (it.isLetter()) {
                if (it.isLowerCase()) {
                    rotateChar(it, 13, 'a', 'z')
                } else {
                    rotateChar(it, 13, 'A', 'Z')
                }
            } else {
                it
            }
        }.joinToString("")

private fun rotateChar(char: Char, shift: Int, lowerBound: Char, upperBound: Char): Char =
        if (char + shift <= upperBound) char + shift else lowerBound - 1 + (char + shift - upperBound)



inline fun <reified T : Any> Array<Array<T>>.transpose(): Array<Array<T>> {
    val width = first().size
    val height = size

    val result = Array(width) { arrayOfNulls<T>(height) }

    for (i in 0 until width) {
        for (j in 0 until height) {
            val ch = this[j][i]
            result[i][j] = ch
        }
    }

    return result.map { it.requireNoNulls() }.toTypedArray()
}

fun <T> Array<Array<T>>.print() {
    forEach { println(it.contentToString()) }
}
