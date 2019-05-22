package cz.vernjan.he19.ch17

import cz.vernjan.he19.ch14.lastEncryptionRound
import cz.vernjan.he19.readAllBytes
import cz.vernjan.he19.toHex
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.Paths

const val WIDTH = 480
const val CHANNELS = 4 // RGBA

fun main() {
    val data = readAllBytes("ch17/eggdesign.png")

    // IDAT HEX: 49 44 41 54,  DEC: 73 68 65 84
    println("Size ${data.size}")

    val bb = ByteBuffer.wrap(data)


    val imageData: MutableList<Byte> = mutableListOf()

    for (i in (0 until data.size)) {
        if (data[i] == 73.toByte()
            && data[i + 1] == 68.toByte()
            && data[i + 2] == 65.toByte()
            && data[i + 3] == 84.toByte()
        ) {
            val chunkLength = bb.getInt(i - 4)

            println("IDAT chunk at $i (length $chunkLength)")

            val chunkData = data.copyOfRange(i + 4, i + 4 + chunkLength)
            println("Parsing IDAT chunk at $i: ${chunkData.copyOfRange(0, 6).map { it.toInt().toHex() }.toList()} ..")
            imageData.addAll(chunkData.toList())

        }
    }

    println("Parsing done, total len: ${imageData.size}")

    val decompress = CompressionUtils.decompress(imageData.toByteArray())

    println("Decompressing done, total len: ${decompress.size}")

    parseOfImageData(decompress)



}


fun parseOfImageData(data: ByteArray) {
//    for (i in (0..4)) {
//        val path = Paths.get("d:\\Shared\\17\\_out$i.png.extracted\\29")
//        val path = Paths.get("d:\\Shared\\17\\simples\\_simple0$i.png.extracted\\29")
//        println("Filtering $i")

//        for (j in (0 until CHANNELS)) {

            val bytes = data.asSequence()
//                .take(1000)
                .filterIndexed { index, value -> filter( {index2 -> index2 % (WIDTH * CHANNELS) != index / (WIDTH * CHANNELS)}, index, value, "filterByte") }
//                .filterIndexed { index, _ -> filter( {index2 -> index2 % CHANNELS != 3}, index, "channel") }
                .toList()
                .toByteArray()

//            Files.write(Paths.get("d:\\Shared\\17\\_out$i.png.extracted\\29-filtered"), bytes)
//            Files.write(Paths.get("d:\\Shared\\17\\_out$i.png.extracted\\29-$j.txt"), bytes)
//            Files.write(Paths.get("d:\\Shared\\17\\_out$i.png.extracted\\29-rgb.txt"), bytes)
//        }
//    }
}

// Congratulation, here is your flag: he19-TKii-2aVa-cKJo-9QCj

fun filter(predicate: (index: Int) -> Boolean, index: Int, value: Byte, name: String): Boolean {
    return if (predicate(index)) {
//        println("Accepting $name/$index")
        true
    } else {

//        println("Refusing $name $value at $index")
        print("$value")
        false
    }
}

