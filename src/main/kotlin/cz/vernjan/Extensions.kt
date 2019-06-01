package cz.vernjan

import org.apache.commons.codec.binary.Hex

fun String.hexToByteArray(): ByteArray = Hex.decodeHex(this)
fun ByteArray.toHex(): String = Hex.encodeHexString(this)

fun String.hexToAscii(): String = String(hexToByteArray())
fun String.asciiToHex(): String = Hex.encodeHexString(toByteArray())