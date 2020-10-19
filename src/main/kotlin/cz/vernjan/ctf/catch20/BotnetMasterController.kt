package cz.vernjan.ctf.catch20

import com.google.common.primitives.Longs
import cz.vernjan.ctf.*
import java.net.Socket
import java.security.MessageDigest

fun main() {
    sendCommand("kl5puyj43brf7iso;;info;;78.128.216.92.20220;;clients")
}

fun sendCommand(command: String) = send("0".repeat(16), sign(command))

fun send(clientId: String, command: String) {
    println("> $command")
    Socket("78.128.216.92", 20220).use { socket ->
        val out = socket.getOutputStream()
        out.write(encode(clientId, command))
        out.flush()

        val response = decode(socket.getInputStream().readAllBytes())
        println("< $response")
    }
}

fun encode(clientId: String, command: String): ByteArray {
    val body = (clientId + command.asciiToHex()).reversed().encodeBase64().toByteArray()
    val length = body.size.toLong()
    return Longs.toByteArray(length).plus(body)
}

fun sign(command: String): String {
    val digest = MessageDigest.getInstance("SHA-384").digest(command.toByteArray()).toHex()
    return "$command;;$digest"
}

fun decode(command: ByteArray) = String(command.drop(8).toByteArray())
        .decodeBase64()
        .reversed()
        .substring(16)
        .hexToAscii()
