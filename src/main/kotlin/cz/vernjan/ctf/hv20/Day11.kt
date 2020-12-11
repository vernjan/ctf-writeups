package cz.vernjan.ctf.hv20

import cz.vernjan.ctf.Resources
import java.awt.Color

fun main() {
    val image = Resources.asImage("hv20/notes.png")
    val message = (0 until image.width).map { x ->
        Color(image.getRGB(x, 0), true)
    }.map {
        decodeColor(it.red) + decodeColor(it.green) + decodeColor(it.blue)
    }.joinToString("")
        .chunked(8).map { Integer.parseInt(it, 2).toChar() }.joinToString("")

    println(message)
}

fun decodeColor(value: Int) = if (value == 254) "1" else "0"