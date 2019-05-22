package cz.vernjan

import java.nio.file.Files
import java.nio.file.Paths
import java.sql.DriverManager
import java.sql.SQLException
import java.util.*

// TODO Refactor this!
fun String.hexToAscii(): String {
    val output = StringBuilder()

    for (i in 0..(length - 2) step 2) {
        val str = substring(i, i + 2)
        output.append(Integer.parseInt(str, 16).toChar())
    }

    return output.toString()
}

fun String.asciiToHex(): String = toCharArray().joinToString { Integer.toHexString(it.toInt()) }

fun Int.toAscii() = Integer.toHexString(this).hexToAscii()
fun Int.toHex() = Integer.toHexString(this).padStart(8, '0')

fun readFile(path: String): String = Files.readString(Paths.get("src/main/kotlin/cz/vernjan/he19/$path"))
//fun readAllBytes(path: String): ByteArray = Files.readAllBytes(Paths.get("src/main/resources/cz/vernjan/he19/$path"))
fun readTestFile(path: String): String = Files.readString(Paths.get("src/test/kotlin/cz/vernjan/he19/$path"))
