package cz.vernjan.ctf.hv19.day09

import cz.vernjan.ctf.Resources
import java.awt.Color
import java.awt.image.BufferedImage
import java.lang.RuntimeException

val SQUARE_SIZE = 5

// TODO to library
fun main() {
    val barcode: BufferedImage = Resources.asImage("hv19/day09/barcode.png")

    for (qrs in 0..100) {


        for (y in 0 until barcode.height step SQUARE_SIZE) {

            val line: List<Boolean> = (0 until barcode.width)
                .asSequence()
                .filter { it % SQUARE_SIZE == 0 }
                .map { i -> barcode.getRGB(i, y) }
                .map { Color(it, true) }
                .map { it.red == 0 }
                .toList()


            var lineX = line.mapIndexed { x, _ -> rule30(line, x) }.toList()
            for (i in 0..qrs) {
                lineX = line.mapIndexed { x, _ -> rule30(lineX, x) }.toList()
            }



            println(
                lineX.joinToString(separator = "") {
                    when (it) {
                        true -> "\u2588\u2588"
                        false -> "  "
                    }
                })

        }
        println()
        println()
        println()
    }
}

fun rule30(line: List<Boolean>, current: Int): Boolean {
    val left = line.getOrNull(current - 1) ?: false
    val middle = line[current]
    val right = line.getOrNull(current + 1) ?: false

    return when {
        left && middle && right -> false
        left && middle && !right -> false
        left && !middle && right -> false
        left && !middle && !right -> true
        !left && middle && right -> true
        !left && middle && !right -> true
        !left && !middle && right -> true
        !left && !middle && !right -> false
        else -> throw RuntimeException("Impossible")
    }

}