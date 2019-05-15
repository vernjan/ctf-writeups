package cz.vernjan.he19.ch14

import org.apache.commons.codec.binary.Hex
import java.nio.ByteBuffer

const val BLOCK_SIZE = 16

fun main() {
    val text = "aaaaaaaaaaaaaaaa"

    // TODO Add padding

    val blockCount = text.length / BLOCK_SIZE
    for (i in (0 until blockCount)) {
        val blockStart = i * BLOCK_SIZE
        val blockEnd = blockStart + BLOCK_SIZE
        val block = text.substring(blockStart, blockEnd)

        val encrypted: ByteArray = encryptBlock(block.toByteArray())

        println("Encrypted: '$block' -> ${Hex.encodeHexString(encrypted)}")
    }
}

// TODO Move to Extensions
class DataLoader {

    companion object {

        private const val OFFSET = 16 * 256 // TODO docs, naming (data1, data2) ..

        private val data: ByteArray = this::class.java.getResourceAsStream("key.data").readAllBytes()

        val data1: ByteArray = data.copyOfRange(0, OFFSET)
        val data2: ByteArray = data.copyOfRange(OFFSET, data.size)

        fun readInt(position: Int): Int = ByteBuffer.wrap(data2.copyOfRange(position, position + 4)).int
    }
}

fun encryptBlock(block: ByteArray): ByteArray {
    println("Encrypting block '${String(block)}'")

    val state = block.copyOf()

    swapRowsWithColumns(state)

    for (round in (0 until 9)) {
        shiftRows(state)
        encryptionRound(round, state)
    }

    shiftRows(state)
    lastEncryptionRound(state)
    swapRowsWithColumns(state)

    return state
}


/**
 * Copy the byte array and swap rows with columns.
 */
fun swapRowsWithColumns(state: ByteArray) { // TODO Explain state in docs (4x4 matrix)
    val temp = ByteArray(BLOCK_SIZE)

    for (i in (0..3)) // TODO unite .. vs. until
        for (j in (0..3))
            temp[4 * i + j] = state[i + 4 * j]

    temp.copyInto(state)
}

/**
 * Shifts rows:
 * 0th row -> No shift
 * 1st row -> Shift by 1
 * 2nd row -> Shift by 2
 * 3rd row -> Shift by 3
 */
fun shiftRows(state: ByteArray) {
    val temp = ByteArray(BLOCK_SIZE)

    temp[0] = state[0]
    temp[1] = state[1]
    temp[2] = state[2]
    temp[3] = state[3]

    temp[4] = state[5]
    temp[5] = state[6]
    temp[6] = state[7]
    temp[7] = state[4]

    temp[8] = state[10]
    temp[9] = state[11]
    temp[10] = state[8]
    temp[11] = state[9]

    temp[12] = state[15]
    temp[13] = state[12]
    temp[14] = state[13]
    temp[15] = state[14]

    temp.copyInto(state)
}

@ExperimentalUnsignedTypes
fun encryptionRound(round: Int, state: ByteArray) {

    for (i in (0 until 4)) {
        var xorAccumulator = 0x0

        for (j in (0 until 4)) {
            val intPosition = (state[i + 4 * j].toUByte().toInt() + 256 * (16 * round + i + 4 * j)) * 4
            val int = DataLoader.readInt(intPosition)
            xorAccumulator = xorAccumulator xor int
        }

        val bytes = ByteBuffer.allocate(4).putInt(xorAccumulator).array()
        for (j in (0 until 4)) {
            state[i + 4 * j] = bytes[j]
        }
    }
}

@ExperimentalUnsignedTypes
fun lastEncryptionRound(state: ByteArray) {
    for (i in (0 until 16))
        state[i] = DataLoader.data1[256 * i + state[i].toUByte().toInt()]
}

