package cz.vernjan.he19.ch14

import cz.vernjan.he19.toHex
import org.apache.commons.codec.binary.Hex
import java.nio.ByteBuffer
import java.util.*

const val BLOCK_SIZE = 16

// TODO Move to Extensions
class DataLoader {

    companion object {

        private const val OFFSET = 16 * 256 // TODO docs, naming (data1, data2) ..

        private val data: ByteArray = this::class.java.getResourceAsStream("key.data").readAllBytes()

        val data1: ByteArray = data.copyOfRange(0, OFFSET)
        val data2: ByteArray = data.copyOfRange(OFFSET, data.size)

        // TODO could be faster
        fun readInt(position: Int): Int = ByteBuffer.wrap(data2.copyOfRange(position, position + 4).reversedArray()).int

        fun readInt3(position: Int): Int = ByteBuffer.wrap(data2.copyOfRange(position, position + 4)).int

        fun readInt2(position: Int): Int = ByteBuffer.wrap(data.copyOfRange(position, position + 4)).int
    }
}

fun encrypt(text: String) {

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

fun decrypt(encrypted: ByteArray) {
    val blockCount = encrypted.size / BLOCK_SIZE
    for (i in (0 until blockCount)) {
        val blockStart = i * BLOCK_SIZE
        val blockEnd = blockStart + BLOCK_SIZE
        val block = encrypted.copyOfRange(blockStart, blockEnd)

        val text: ByteArray = decryptBlock(block)

        println("Decrypted: '${Hex.encodeHexString(block)}' -> ${String(text)}")
    }
}

fun encryptBlock(block: ByteArray): ByteArray {
    println("Encrypting block '${String(block)}'")

    val state = block.copyOf()

    swapRowsWithColumns(state)

    for (round in (0 until 9)) {
        shiftRows(state)
        encryptionRound(round, state) // TODO name
    }

    shiftRows(state)
    lastEncryptionRound(state)
    swapRowsWithColumns(state)

    return state
}

fun decryptBlock(block: ByteArray): ByteArray {
    println("Decrypting block '${Hex.encodeHexString(block)}'")

    val state = block.copyOf()

    swapRowsWithColumns(state)
    undoLastEncryptionRound(state)
    undoShiftRows(state)

    for (round in (8 downTo 0)) {
        undoEncryptionRound(round, state) // UNDO
        undoShiftRows(state)
    }

    swapRowsWithColumns(state)

    return state
}

/**
 * Copy the byte array and swap rows with columns.
 */
fun swapRowsWithColumns(state: ByteArray) { // TODO Explain state in docs (4x4 matrix)
    val temp = ByteArray(BLOCK_SIZE)

    for (i in (0 until 4))
        for (j in (0 until 4))
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
    val temp = state.copyOf()

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

fun undoShiftRows(state: ByteArray) {
    val temp = state.copyOf()

    temp[4] = state[7]
    temp[5] = state[4]
    temp[6] = state[5]
    temp[7] = state[6]

    temp[8] = state[10]
    temp[9] = state[11]
    temp[10] = state[8]
    temp[11] = state[9]

    temp[12] = state[13]
    temp[13] = state[14]
    temp[14] = state[15]
    temp[15] = state[12]

    temp.copyInto(state)
}

@ExperimentalUnsignedTypes
fun encryptionRound(round: Int, state: ByteArray) {
    println()
    println("Round $round:")

    for (i in (0 until 4)) {
        var xorAccumulator = 0x0

        for (j in (0 until 4)) {
            val index = i + 4 * j
            val intPosition = (state[index].toUByte().toInt() + 256 * (16 * round + i + 4 * j)) * 4
            val int = DataLoader.readInt(intPosition)

            println(
                "Index ${index.toString().padStart(2, '0')}\t->" +
                        " $intPosition (0x${Integer.toHexString(intPosition + 4096)})\t" +
                        "-> $int ${int.toHex()}"
            )

            xorAccumulator = xorAccumulator xor int
        }

        println("Xor: $xorAccumulator (${xorAccumulator.toHex()})")

        val bytes = ByteBuffer.allocate(4).putInt(xorAccumulator).array().reversedArray()
        for (j in (0 until 4)) {
            state[i + 4 * j] = bytes[j]
        }
    }

    println("State after ${Hex.encodeHexString(state)}")
}

@ExperimentalUnsignedTypes
fun undoEncryptionRound(round: Int, state: ByteArray) {
    println()
    println("Round $round:")

    for (i in (0 until 4)) {

        val xorResult = ByteArray(4)
        for (j in (0 until 4)) {
//            println("Composing XOR to be reverted: ${Integer.toHexString(state[i + 4 * j].toInt())}")
            xorResult[3 - j] = state[i + 4 * j] // TOOD maybe j - 3
        }
        val foo = ByteBuffer.wrap(xorResult).int
//        println("${foo.toHex()}")
        val originalIntegers = undoXor(round, i, foo)

//        println("Found ${Arrays.toString(originalIntegers)}")

//        Found [1748379074, -626411805, 1403794018, -1317534635]
//        Found [1023743652, -1228575145, -305402916, 1682629554]

        for (originalInteger in originalIntegers.withIndex()) {
            state[i + 4 * originalInteger.index] = loadArray(round, i, originalInteger.index).withIndex()
                .find { (_, value) -> value == originalInteger.value }
                ?.index?.toByte() ?: throw AssertionError("Failed to find the original index for value: ${state[i]}")
        }

        // TODO search indexes, set to state


//            val index = i + 4 * j
//            val intPosition = (state[index].toUByte().toInt() + 256 * (16 * round + i + 4 * j)) * 4
//            val int = DataLoader.readInt(intPosition)

//            println(
//                "Index ${index.toString().padStart(2, '0')}\t->" +
//                        " $intPosition (0x${Integer.toHexString(intPosition + 4096)})\t" +
//                        "-> $int ${int.toHex()}"
//            )

//            xorAccumulator = xorAccumulator xor int
        }

//        println("Xor: $xorAccumulator (${xorAccumulator.toHex()})")

//        val bytes = ByteBuffer.allocate(4).putInt(xorAccumulator).array()
//        for (j in (0 until 4)) {
//            state[i + 4 * j] = bytes[3 - j]
//        }
//    }
}

@ExperimentalUnsignedTypes
fun lastEncryptionRound(state: ByteArray) {
    for (i in (0 until 16))
        state[i] = DataLoader.data1[256 * i + state[i].toUByte().toInt()]
}

@ExperimentalUnsignedTypes
fun undoLastEncryptionRound(state: ByteArray) { // TODO need to search indexes ..
    for (i in (0 until 16)) {
        val start = 256 * i
        state[i] = DataLoader.data1.copyOfRange(start, start + 256).withIndex()
            .find { (_, value) -> value == state[i] }
            ?.index?.toByte() ?: throw AssertionError("Failed to find the original index for value: ${state[i]}")
    }
}

// TODO new Class / File
fun undoXor(round: Int, i: Int, xorResult: Int): IntArray {
    println("Reversing XOR of ${xorResult.toHex()}")

    val array0 = loadArray(round, i, 0)
    val array1 = loadArray(round, i, 1)
    val array2 = loadArray(round, i, 2)
    val array3 = loadArray(round, i, 3)

    for (a in array0)
        for (b in array1)
            for (c in array2)
                for (d in array3)
                    if (a xor b xor c xor d == xorResult) {
                        println("Found: ${Arrays.toString(intArrayOf(a, b, c, d))}")
                        return intArrayOf(a, b, c, d)
                    }

    throw AssertionError("Failed to undo XOR for round: $round, i: $i and number: ${xorResult.toHex()}")
}

fun loadArray(round: Int, i: Int, j: Int): IntArray {
    val start = 256 * (16 * round + i + 4 * j) * 4
    return (start until start + 1024 step 4).map { DataLoader.readInt(it) }.toIntArray()
}
