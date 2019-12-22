package cz.vernjan.ctf.hv19.day20

import java.nio.file.Files
import java.nio.file.Paths
import kotlin.experimental.xor

fun main() {
    val flagAccumulator = mutableListOf(0xce.toByte(), 0x55.toByte(), 0x95.toByte(), 0x4e.toByte(), 0x38.toByte(), 0xc5.toByte(), 0x89.toByte(), 0xa5.toByte(), 0x1b.toByte(), 0x6f.toByte(), 0x5e.toByte(), 0x25.toByte(), 0xd2.toByte(), 0x1d.toByte(), 0x2a.toByte(), 0x2b.toByte(), 0x5e.toByte(), 0x7b.toByte(), 0x39.toByte(), 0x14.toByte(), 0x8e.toByte(), 0xd0.toByte(), 0xf0.toByte(), 0xf8.toByte(), 0xf8.toByte(), 0xa5.toByte())
    val fileData = Files.readAllBytes(Paths.get("d:\\Temp\\505Retail.PUP"))

    for (i in 0x1337 until 0x1714908 step 0x1337) {
        val chunk = fileData.copyOfRange(i, i + 26)
        chunk.forEachIndexed{j, chunkByte ->
            flagAccumulator[j] = (chunkByte xor flagAccumulator[j])
        }
    }

    println(String(flagAccumulator.toByteArray()))
}


























