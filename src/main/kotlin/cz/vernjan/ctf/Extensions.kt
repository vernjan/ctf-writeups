package cz.vernjan.ctf

import org.apache.commons.codec.binary.Hex
import java.util.*

private val base64Decoder = Base64.getDecoder()

fun String.hexToByteArray(): ByteArray = Hex.decodeHex(this)
fun ByteArray.toHex(): String = Hex.encodeHexString(this)

fun String.hexToAscii(): String = String(hexToByteArray())
fun String.asciiToHex(): String = Hex.encodeHexString(toByteArray())

fun String.decodeBase64() : String = String(base64Decoder.decode(this))

fun Int.toHex(): String = Integer.toHexString(this)