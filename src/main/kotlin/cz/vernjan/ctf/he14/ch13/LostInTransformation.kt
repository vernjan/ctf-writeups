package cz.vernjan.ctf.he14.ch13

import cz.vernjan.ctf.Resources
import cz.vernjan.ctf.decodeBase64
import cz.vernjan.ctf.hexToAscii
import cz.vernjan.ctf.rot13
import org.apache.commons.codec.binary.Base32
import java.net.URLDecoder
import kotlin.system.exitProcess

fun main() {

    var text = Resources.asString("he14/ch13/lost-in-transformation.txt")

    while (true) {
        println(text)

        if (!text.startsWith("[")) {
            break
        }

        val (head, tail) = text.split("]", limit = 2)
        val id = head.substring(1).split(":").first()
        val op = head.split(":").last()

        println("ID: $id")
        println("OP: $op")

        text = when (op) {
            "b64" -> tail.decodeBase64()
            "b32" -> Base32().decode(tail).toString(Charsets.US_ASCII)
            "hex" -> tail.hexToAscii()
            "inv" -> tail.reverseCase()
            "url" -> URLDecoder.decode(tail, Charsets.US_ASCII.name())
            "r13" -> tail.rot13()
            "xxx" -> tail.substring(3, tail.length - 3)
            "rev" -> tail.reversed()
            "nop" -> tail
            else -> exitProcess(1)
        }

        println("---")
    }

}

private fun String.reverseCase(): String = map {
    if (it.isUpperCase()) it.toLowerCase() else it.toUpperCase()
}.joinToString("")
