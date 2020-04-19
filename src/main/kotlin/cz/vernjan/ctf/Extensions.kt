package cz.vernjan.ctf

import org.apache.commons.codec.binary.Hex
import java.util.*

private val base64Decoder = Base64.getDecoder()

fun String.hexToByteArray(): ByteArray = Hex.decodeHex(this)
fun ByteArray.toHex(): String = Hex.encodeHexString(this)

fun String.hexToAscii(): String = String(hexToByteArray())
fun String.asciiToHex(): String = Hex.encodeHexString(toByteArray())

fun String.decodeBase64(): String = String(base64Decoder.decode(this))

fun Int.toHex(): String = Integer.toHexString(this)

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
