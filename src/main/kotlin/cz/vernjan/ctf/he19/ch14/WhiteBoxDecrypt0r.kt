package cz.vernjan.ctf.he19.ch14

import cz.vernjan.ctf.toHex
import org.apache.commons.codec.binary.Hex
import java.nio.ByteBuffer
import java.util.*

@ExperimentalUnsignedTypes
object Decrypt0r {

    fun decrypt(encrypted: ByteArray) {
        val blockCount = encrypted.size / BLOCK_SIZE
        for (i in (0 until blockCount)) {
            val blockStart = i * BLOCK_SIZE
            val blockEnd = blockStart + BLOCK_SIZE
            val block = encrypted.copyOfRange(blockStart, blockEnd)

            val textBlock: ByteArray = decryptBlock(block)

            println("Decrypted: '${Hex.encodeHexString(block)}' -> ${String(textBlock)}")
        }
    }

    fun decryptBlock(block: ByteArray): ByteArray {
        println("Decrypting block '${Hex.encodeHexString(block)}'")

        val state = block.copyOf()

        swapRowsWithColumns(state)
        undoLastEncryptionRound(state)
        undoShiftRows(state)

        for (round in (8 downTo 0)) {
            undoBasicEncryptionRound(round, state)
            undoShiftRows(state)
        }

        swapRowsWithColumns(state)

        return state
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

    fun undoBasicEncryptionRound(round: Int, state: ByteArray) {
        println("\nRound $round:")

        for (i in (0 until 4)) {
            val xorResult = ByteArray(4)

            for (j in (0 until 4)) {
                xorResult[3 - j] = state[i + 4 * j]
            }

            val xorResultAsInt = ByteBuffer.wrap(xorResult).int
            val originalIntegers = undoXor(round, i, xorResultAsInt)

            for (originalInteger in originalIntegers.withIndex()) {
                state[i + 4 * originalInteger.index] = loadRoundKeys(round, i, originalInteger.index).withIndex()
                    .find { (_, value) -> value == originalInteger.value }
                    ?.index?.toByte()
                    ?: throw AssertionError("Failed to find the original index for value: ${state[i]}")
            }
        }
    }

    private fun loadRoundKeys(round: Int, i: Int, j: Int): IntArray {
        val start = 256 * (16 * round + i + 4 * j) * 4
        return (start until start + 1024 step 4).map { KeyDataLoader.readBasicRoundKey(it) }.toIntArray()
    }

    fun undoLastEncryptionRound(state: ByteArray) {
        for (i in (0 until BLOCK_SIZE)) {
            val start = 256 * i
            state[i] = KeyDataLoader.lastRoundKesData.copyOfRange(start, start + 256).withIndex()
                .find { (_, value) -> value == state[i] }
                ?.index?.toByte()
                ?: throw AssertionError("Failed to find the original index for value: ${state[i]}")
        }
    }

    fun undoXor(round: Int, i: Int, xorResult: Int): IntArray {
        println("Reversing XOR of ${xorResult.toHex().padStart(8, '0')}")

        val roundKeys1 = loadRoundKeys(round, i, 0)
        val roundKeys2 = loadRoundKeys(round, i, 1)
        val roundKeys3 = loadRoundKeys(round, i, 2)
        val roundKeys4 = loadRoundKeys(round, i, 3)

        for (a in roundKeys1)
            for (b in roundKeys2)
                for (c in roundKeys3)
                    for (d in roundKeys4)
                        if (a xor b xor c xor d == xorResult) {
                            println("Found: ${Arrays.toString(intArrayOf(a, b, c, d))}")
                            return intArrayOf(a, b, c, d)
                        }

        throw AssertionError("Failed to undo XOR for round: $round, i: $i and number: ${xorResult.toHex()}")
    }

}
