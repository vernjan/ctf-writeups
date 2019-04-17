package cz.vernjan.he19

import java.nio.file.Files
import java.nio.file.Paths

fun String.hexToAscii(): String {
    val output = StringBuilder()

    for (i in 0..(length - 2) step 2) {
        val str = substring(i, i + 2)
        output.append(Integer.parseInt(str, 16).toChar())
    }

    return output.toString()
}

fun String.asciiToHex(): String = toCharArray().joinToString { Integer.toHexString(it.toInt()) }

fun readFile(path: String): String = Files.readString(Paths.get("src/cz/vernjan/he19/$path"))