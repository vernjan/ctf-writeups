package cz.vernjan.ctf.catch19

import cz.vernjan.ctf.Resources
import cz.vernjan.ctf.hexToAscii

fun main() {
    val pieces = Resources.asString("catch19/seventh-element.txt")
        .lines()
        .chunked(2)
        .map { MessagePart(it[0].hexToAscii(), it[1].substring(2).toInt(16)) }
        .mapIndexed { index, messagePart -> index to messagePart }
        .toMap()

    // brute force all possible starts of messages
    for (i in 0..127) {
        var current: MessagePart = pieces.getValue(i)

        while (current.next != 255) { // 255 means end of cycle
            print(current.content)
            current = pieces.getValue(current.next)
        }
        println()
    }
}

data class MessagePart(val content: String, val next: Int)