package cz.vernjan.ctf.he21

import cz.vernjan.ctf.decodeBase64

fun main() {
    val encrypted = "2Qu93ZhJHdsMGIlhmcgUXagMWe19icmBGbnFiOoBTZwIjM7FGd0gHdfNTbuB2a5V2X1JzcuF3MzNQf=="
    val decrypted = arrayOfNulls<Char>(encrypted.length)

    encrypted.forEachIndexed { index, _ ->
        if (index % 2 == 0) {
            decrypted[index] = encrypted[index + 1]
            decrypted[index + 1] = encrypted[index]
        }
    }

    println(decrypted.joinToString("").decodeBase64())
}