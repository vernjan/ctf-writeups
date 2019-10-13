package cz.vernjan.ctf.catch19

import cz.vernjan.ctf.Resources
import cz.vernjan.ctf.hexToAscii

fun main() {
//    Resources.asString("catch19/pieces.txt")
//        .split("\n")
//        .chunked(2)
//        .map { MessagePart(it[0].hexToAscii(), it[1].substring(2).toInt(16)) }
//        .forEachIndexed { i, message -> println("$i\t$message") }

    val pieces = Resources.asString("catch19/pieces.txt")
        .split("\n")
        .chunked(2)
        .map { MessagePart(it[0].hexToAscii(), it[1].substring(2).toInt(16)) }
        .mapIndexed { index, messagePart -> index to messagePart }
        .toMap()

    for (j in 0..127) {

        var current: MessagePart = pieces.getValue(j)
        for (i in 0..127) {
            print(current.content)
            if (current.order == 255) break
            current = pieces.getValue(current.order)
        }
        println()
    }
}

data class MessagePart(val content: String, val order: Int)