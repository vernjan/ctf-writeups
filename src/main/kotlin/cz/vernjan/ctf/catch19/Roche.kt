package cz.vernjan.ctf.catch19

import cz.vernjan.ctf.hexToByteArray
import java.lang.StringBuilder
import kotlin.experimental.xor

fun main() {

    val cipherText =
        "463216327617246f67406f1266075ec622606c6671765537066636596e621e64e622c2b006066961c66e621f067676e77c6e665167a462c4b50477433617754222d7043542885747df6dd575970417d435223000"
//    val keys = listOf("roche", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")
    val keys = 'a'..'z'

    for (len in 4..16) {
        println()
        println("Length: $len")
        keys.forEach { key ->
            println()
            println("Key: $key")
            var noped = false
            val out = StringBuilder()
            for ((i, cipherTextByte) in cipherText.hexToByteArray().withIndex()) {
                if (i % len == 0) {
                    val decrypted = cipherTextByte.xor(key.toByte())
                    out.append(decrypted.toChar())
                    print(decrypted.toChar())
                    if (decrypted !in 32..127 && decrypted !=10.toByte()) {
                        noped = true

//                        print(" Nope!")
                        break
                    }

//                    print(decrypted.toChar())
                }

//                val keyShift = key[i % key.length].toByte() - 'a'.toByte()

//            val decrypted = cipherTextByte - keyShift
//            println("$cipherTextByte + $keyShift = $decrypted (${decrypted.toChar()})")

//            println("$i: $keyByte: $byte")

            }
            if (!noped || out.length >= 7) {

                println("YES: $out")
            }

        }
//        println()
//        println("***")
    }


}