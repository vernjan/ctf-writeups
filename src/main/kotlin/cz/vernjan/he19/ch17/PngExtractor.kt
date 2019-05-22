package cz.vernjan.he19.ch17

import cz.vernjan.ZlibUtils
import java.nio.ByteBuffer

private const val WIDTH = 480
private const val CHANNELS = 4 // RGBA
private const val BYTES_PER_ROW = WIDTH * CHANNELS

fun main() {
    val data = PngExtractor::class.java.getResourceAsStream("eggdesign.png").readAllBytes()
    val imageData: ByteArray = PngExtractor.extractImageData(data)
    val decompressedImageData: ByteArray = ZlibUtils.decompress(imageData)
    val filterTypeBytes = PngExtractor.extractFilterTypes(decompressedImageData)

    val secretMessage = filterTypeBytes.asSequence()
        .windowed(size = 8, step = 8)
        .map { Integer.parseInt(it.joinToString(separator = ""), 2) }
        .map { it.toChar() }
        .joinToString(separator = "")

    println(secretMessage)
}


object PngExtractor {

    /**
     * Extract all IDAT chunks into a single byte array.
     */
    fun extractImageData(imageData: ByteArray): ByteArray {
        val imageDataBuffer = ByteBuffer.wrap(imageData)
        val chunks: MutableList<Byte> = mutableListOf()
        for (i in (0 until imageData.size)) {
            if (isStartOfIDAT(imageData, i)) {
                val chunkLength = imageDataBuffer.getInt(i - 4)

                println("Detecting IDAT chunk at $i (length $chunkLength)")

                val chunkData = imageData.copyOfRange(i + 4, i + 4 + chunkLength)
                chunks.addAll(chunkData.toList())
            }
        }
        return chunks.toByteArray()
    }

    /**
     * IDAT chunks starts with 4 bytes 73 68 65 84 (in decimal).
     */
    private fun isStartOfIDAT(imageData: ByteArray, i: Int) = imageData[i] == 73.toByte()
            && imageData[i + 1] == 68.toByte()
            && imageData[i + 2] == 65.toByte()
            && imageData[i + 3] == 84.toByte()

    /**
     * Each row may use a different filter type (0-4). Filter type is defined by a single byte preceding the row data.
     */
    fun extractFilterTypes(data: ByteArray): ByteArray {
        return data.asSequence()
            .filterIndexed { index, _ -> index % BYTES_PER_ROW == index / BYTES_PER_ROW }
            .toList()
            .toByteArray()
    }
}
