package cz.vernjan.ctf.catch20

import cz.vernjan.ctf.Resources
import cz.vernjan.ctf.decodeBase64

fun main() {
    val messages = Resources.asString("catch20/message")

    var message = StringBuilder()
    var skipNext = false

    messages.forEach { ch ->
        if (!skipNext) {
            if (ch.toByte() < 0x20) {
                println(message.toString().decodeBase64())
                message = StringBuilder()
                skipNext = true
            } else {
                message.append(ch)
            }
        } else {
            skipNext = false
        }
    }
}