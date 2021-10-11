package cz.vernjan.ctf.catch21

import cz.vernjan.ctf.Resources
import cz.vernjan.ctf.decodeBase64

fun main() {
    var data = Resources.asString("catch21/DarkSide-data.txt").decodeBase64()

    while (data.contains(";")) {
        val (message, tail) = data.split(";")
        print(message)
        data = tail.decodeBase64()
    }
}