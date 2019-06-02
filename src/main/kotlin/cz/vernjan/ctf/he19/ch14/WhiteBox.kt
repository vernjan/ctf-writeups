package cz.vernjan.ctf.he19.ch14

import cz.vernjan.ctf.Resources
import cz.vernjan.ctf.hexToByteArray
import java.nio.ByteBuffer

const val BLOCK_SIZE = 16

@ExperimentalUnsignedTypes
fun main() {
    val encrypted = "9771a6a9aea773a93edc1b9e82b745030b770f8f992d0e45d7404f1d6533f9df" +
            "348dbccd71034aff88afd188007df4a5c844969584b5ffd6ed2eb92aa419914e"

    Decrypt0r.decrypt(encrypted.hexToByteArray())
}

/**
 * Copy the byte array and swap rows with columns.
 * Array is 16 bytes, i.e. 4x4 matrix.
 */
fun swapRowsWithColumns(matrix: ByteArray) {
    val temp = ByteArray(BLOCK_SIZE)

    for (i in (0 until 4))
        for (j in (0 until 4))
            temp[4 * i + j] = matrix[i + 4 * j]

    temp.copyInto(matrix)
}

object KeyDataLoader {

    private const val BASIC_ROUND_KEYS_OFFSET = 16 * 256

    private val keyData: ByteArray = Resources.asBytes("he19/ch14/key.data")
    private val basicRoundKeysData: ByteArray = keyData.copyOfRange(BASIC_ROUND_KEYS_OFFSET, keyData.size)
    val lastRoundKesData: ByteArray = keyData.copyOfRange(0, BASIC_ROUND_KEYS_OFFSET)

    fun readBasicRoundKey(position: Int): Int
            = ByteBuffer.wrap(basicRoundKeysData.copyOfRange(position, position + 4).reversedArray()).int

}