package cz.vernjan.ctf.catch19

import cz.vernjan.ctf.Resources
import cz.vernjan.ctf.hexToAscii

fun main() {
    Resources.asString("catch19/seventh-element.txt")
        .split("\n")
        .chunked(2)
        .map { MessagePart(it[0].hexToAscii(), it[1].substring(2).toInt(16)) }
        .sortedBy { it.order }
        .forEachIndexed { i, msg -> println("${i + 1}\t$msg") }
//        .forEach { print(it.content) }
}

data class MessagePart(val content: String, val order: Int)