package cz.vernjan.ctf.he19.ch14

import cz.vernjan.ctf.toHex
import org.apache.commons.codec.binary.Hex
import java.nio.ByteBuffer

@ExperimentalUnsignedTypes
object Encrypt0r {

    fun encrypt(text: String) {

        // TODO Add padding

        val blockCount = text.length / BLOCK_SIZE
        for (i in (0 until blockCount)) {
            val blockStart = i * BLOCK_SIZE
            val blockEnd = blockStart + BLOCK_SIZE
            val block = text.substring(blockStart, blockEnd)

            val encryptedBlock: ByteArray = encryptBlock(block.toByteArray())

            println("Encrypted: '$block' -> ${Hex.encodeHexString(encryptedBlock)}")
        }
    }

    fun encryptBlock(block: ByteArray): ByteArray {
        println("Encrypting block '${String(block)}'")

        val state = block.copyOf()

        swapRowsWithColumns(state)

        for (round in (0 until 9)) {
            shiftRows(state)
            basicEncryptionRound(round, state)
        }

        shiftRows(state)
        lastEncryptionRound(state)
        swapRowsWithColumns(state)

        return state
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

    fun basicEncryptionRound(round: Int, state: ByteArray) {
        println("\nRound $round:")

        for (i in (0 until 4)) {
            var xorAccumulator = 0x0

            for (j in (0 until 4)) {
                val index = i + 4 * j
                val intPosition = (state[index].toUByte().toInt() + 256 * (16 * round + index)) * 4
                val partialKey = KeyDataLoader.readBasicRoundKey(intPosition)

                println(
                    "Index ${index.toString().padStart(2, '0')}\t->" +
                            " $intPosition (0x${(intPosition + 4096).toHex()})\t" +
                            "-> $partialKey ${partialKey.toHex().padStart(8, '0')}"
                )

                xorAccumulator = xorAccumulator xor partialKey
            }

            println("Xor: $xorAccumulator (${xorAccumulator.toHex().padStart(8, '0')})")

            val bytes = ByteBuffer.allocate(4).putInt(xorAccumulator).array().reversedArray()
            for (j in (0 until 4)) {
                state[i + 4 * j] = bytes[j]
            }
        }

        println("State after ${Hex.encodeHexString(state)}")
    }

    fun lastEncryptionRound(state: ByteArray) {
        for (i in (0 until 16))
            state[i] = KeyDataLoader.lastRoundKesData[256 * i + state[i].toUByte().toInt()]
    }

}