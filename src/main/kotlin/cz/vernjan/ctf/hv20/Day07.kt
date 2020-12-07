package cz.vernjan.ctf.hv20

import cz.vernjan.ctf.decodeBase64
import java.security.MessageDigest
import java.util.*
import kotlin.experimental.xor
import kotlin.system.exitProcess

val sha1Expected = listOf(107, 64, 119, 202, 154, 218, 200, 113, 63, 1, 66, 148, 207, 23, 254, 198, 197, 79, 21, 10)

fun main() {

    unscrambleDinosAreLit() // nOMNSaSFjC[

    for (unknown1 in 0..9) {
        for (unknown2 in ('A'..'Z')) { // Try all Base64 valid chars

            val s1 = "SFYyMHtyMz%dzcnMzXzNuZzFuMzNyMW5n%s200ZDNfMzRzeX0=".format(unknown1, unknown2.toString())
            val a1 = Base64.getDecoder().decode(s1)
            val s2 = "Q1RGX3hsNHoxbmnf"
            val a2 = Base64.getDecoder().decode(s2)

            val a3 = a1.mapIndexed { index, b -> b.xor(a2[index % a2.size]) }.toByteArray()

            val sha1 = MessageDigest
                    .getInstance("SHA-1")
                    .digest(a3).toList().map { it.toUByte().toInt() }

            if (sha1 == sha1Expected) {
                println("YES!!")
                println(s1.decodeBase64()) // The flag
                exitProcess(0)
            }
        }
    }
}

private fun unscrambleDinosAreLit() {
    val s = "DinosAreLit"
    var b = 42
    for (i in s.indices) {
        print(s[i].toInt().xor(b).toChar())
        b += i - 4
    }
    println()
}