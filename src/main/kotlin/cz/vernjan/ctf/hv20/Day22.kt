package cz.vernjan.ctf.hv20

import cz.vernjan.ctf.Resources
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.system.exitProcess

private const val START_OFFSET = 0x124B

fun main() {
    val data = Resources.asBytes("hv20/padawanlock")

    for (i in 0..999999) {
        val message = StringBuilder()
        var offset = START_OFFSET + i * 0x14

        while (offset != 0x1226) { // Address of the final jump
            val char = data[offset + 13].toChar()
            message.append(char)

            val rip = offset + 20
            val jmp = ByteBuffer.wrap(data.copyOfRange(offset + 16, offset + 20))
                .order(ByteOrder.LITTLE_ENDIAN)
                .getInt(0)

            offset = jmp + rip
        }
        if (message.startsWith("HV20{")) {
            println("PIN: $i")
            println(message.toString())
            exitProcess(0)
        }
    }
}