package cz.vernjan.he19.ch14

import org.apache.commons.codec.binary.Hex

const val BLOCK_SIZE = 16

fun main() {
    val text = "Hello, encrypt me, nice please!!"

    // TODO padding

    val blockCount = text.length / BLOCK_SIZE
    for (i in (0 until blockCount)) {
        val blockStart = i * BLOCK_SIZE
        val blockEnd = blockStart + BLOCK_SIZE
        val block = text.substring(blockStart, blockEnd)
        val encrypted: ByteArray = encryptBlock(block.toByteArray())
        println("Encrypted: '$block' -> ${Hex.encodeHexString(encrypted)}")
    }
}

// TODO to Extensions
class DataLoader {

//    val data: ByteArray = this::class.java.getResourceAsStream("key.data").readAllBytes()
//
    companion object {
        val data: ByteArray = this::class.java.getResourceAsStream("key.data").readAllBytes()
//        fun readKeyData(): ByteArray = this::class.java.getResourceAsStream("key.data").readAllBytes()
    }
}


fun encryptBlock(block: ByteArray): ByteArray {
    println("Encrypting block '${String(block)}'")

    var state = copyAndSwap(block)

    for (i in (0 until 9)) {
        state = shiftRows(state)
    }

    state = shiftRows(state)
    // TODO
    state = copyAndReverseSwap(state)

    return block
}


/**
 * Copy the byte array and swap rows with columns.
 */
fun copyAndSwap(source: ByteArray): ByteArray { // TODO all methods void??
    val copy = ByteArray(BLOCK_SIZE)

    for (i in (0..3))
        for (j in (0..3))
            copy[4 * i + j] = source[i + 4 * j]

    return copy
}

fun copyAndReverseSwap(source: ByteArray): ByteArray { // TODO all methods void??
    val copy = ByteArray(BLOCK_SIZE)

    for (i in (0..3))
        for (j in (0..3))
            copy[i + 4 * j] = source[4 * i + j]

    return copy
}

/**
 * Shifts rows:
 * 0th row -> No shift
 * 1st row -> Shift by 1
 * 2nd row -> Shift by 2
 * 3rd row -> Shift by 3
 */
fun shiftRows(source: ByteArray): ByteArray {
    val copy = ByteArray(BLOCK_SIZE)

    copy[0] = source[0]
    copy[1] = source[1]
    copy[2] = source[2]
    copy[3] = source[3]

    copy[4] = source[7]
    copy[5] = source[4]
    copy[6] = source[5]
    copy[7] = source[6]

    copy[8] = source[10]
    copy[9] = source[11]
    copy[10] = source[8]
    copy[11] = source[9]

    copy[12] = source[13]
    copy[13] = source[14]
    copy[14] = source[15]
    copy[15] = source[12]

    return copy
}

fun loadKey(state: ByteArray) {
//    val copy = ByteArray(BLOCK_SIZE)

    for (i in (0..3))
        for (j in (0..3)) {
            val index = i * 4 + j // TODO we could just do (0..15)
            state[index] = DataLoader.data[256 * index + state[index]] // Note: access from 0 to 16*256 (ie 4096)
        }
}

//void readFrom0x602060(long *state) { // 400a7a
//    int i = 0;
//    while (i < 4) {
//        int j = 0;
//        while (j < 4) {
//            // FIXME rewrite so this makes sense (once I'm sure about it)
//            *(state + i * 4 + j) = (&DAT_00602060) [*(byte *) (state + i * 4 + j) + (i * 4 + j) * 0x100]; // 256
//            // TODO maybe this is a value from state .. ! WOULD MAKE SENSE: DATA[state[i] + 256*i] YES: 512*256 = 131,072
//            j++;
//        }
//        i++;
//    }
//}
