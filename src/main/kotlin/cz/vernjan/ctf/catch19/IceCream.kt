package cz.vernjan.ctf.catch19

import cz.vernjan.ctf.Resources
import cz.vernjan.ctf.hexToAscii
import java.net.URL
import java.nio.file.Files
import java.nio.file.Paths

/**
 * Blind alley ..
 */
fun main() {
    val httpUrl: URL = Resources::class.java.getResource("catch19/http")
    val httpPath = Paths.get(httpUrl.toURI())
    Files.list(httpPath).forEach {
        println(it)
        val content = Files.readString(it)
        println(content)
        Files.readAllLines(it)
            .map { line -> line.hexToAscii() }
            .forEach { line -> println(line)}
    }
}