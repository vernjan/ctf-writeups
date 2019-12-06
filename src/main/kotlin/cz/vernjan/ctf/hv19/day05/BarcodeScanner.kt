package cz.vernjan.ctf.hv19.day05

import cz.vernjan.ctf.Resources
import java.awt.Color
import java.awt.image.BufferedImage

fun main() {
    val barcode: BufferedImage = Resources.asImage("hv19/day05/barcode.png")

    val colors: List<Color> = (0 until barcode.width)
        .map { i -> barcode.getRGB(i, 0) }
        .map { Color(it, true) }
        .toList()

    var lastColor = Color.WHITE
    var counter = 0
    for (color in colors) {
        if (color == Color.WHITE || color == lastColor) {
            continue
        }
        print(color.blue.toChar())
        lastColor = color
        counter++
    }
}
