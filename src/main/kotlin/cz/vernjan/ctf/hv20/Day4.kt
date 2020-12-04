package cz.vernjan.ctf.hv20

import cz.vernjan.ctf.hexToAscii
import cz.vernjan.ctf.toHex

fun main() {
    val beads = "GPRYPGBPRGPGBPRGBYPGBYPGBPBYPBYPGBYPRYPBYPPGBYPGYPGYPBYPBYPGPGBPRGBPBYPGBYPBYPGP"

    val flag = beads.split('P').dropLast(1)
        .map { group ->
            "RGBY".map { color -> if (group.contains(color)) "1" else "0" }.joinToString("")
        }
        .map { Integer.parseInt(it, 2) }
        .map { it.toHex() }
        .chunked(2)
        .map { it.joinToString("") }
        .joinToString("") { it.hexToAscii() }

    println(flag)
}