package cz.vernjan.ctf.he19.ch03

import cz.vernjan.ctf.hexToAscii
import java.math.BigInteger
import java.util.*

private val KEY = BigInteger("5".repeat(101))

fun main() {
    val encrypted = "K7sAYzGlYx0kZyXIIPrXxK22DkU4Q+rTGfUk9i9vA60C/ZcQOSWNfJLTu4RpIBy/27yK5CBW+UrBhm0="
    val decoded: ByteArray = Base64.getDecoder().decode(encrypted)
    val decrypted: BigInteger = BigInteger(decoded).divide(KEY)
    println(decrypted.toString(16).hexToAscii())
}