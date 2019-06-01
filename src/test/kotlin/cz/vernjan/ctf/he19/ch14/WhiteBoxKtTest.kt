package cz.vernjan.ctf.he19.ch14

import org.apache.commons.codec.binary.Hex
import org.junit.Test

import org.junit.Assert.*

class WhiteBoxKtTest {

    @Test
    fun swapRowsWithColumns() {
        val state = "0123456789abcdef".toByteArray()

        swapRowsWithColumns(state)

        assertEquals("048c159d26ae37bf", String(state))
    }

    @Test
    fun undoSwapRowsWithColumns() {
        val state = "048c159d26ae37bf".toByteArray()

        swapRowsWithColumns(state)

        assertEquals("0123456789abcdef", String(state))
    }

    @Test
    fun shiftRows() {
        val state = "0123456789abcdef".toByteArray()

        shiftRows(state)

        assertEquals("01235674ab89fcde", String(state))
    }

    @Test
    fun undoShiftRows() {
        val state = "01235674ab89fcde".toByteArray()

        undoShiftRows(state)

        assertEquals("0123456789abcdef", String(state))
    }

    @Test
    fun encryptionRound() {
        val state = "abcdefghijklmnop".toByteArray()

        encryptionRound(0, state)

        assertArrayEquals(Hex.decodeHex("5002e5ac4b41367fa570630f169d869b"), state)
    }

    @Test
    fun undoEncryptionRound() {
        val state = Hex.decodeHex("5002e5ac4b41367fa570630f169d869b")

        undoEncryptionRound(0, state)

        assertArrayEquals("abcdefghijklmnop".toByteArray(), state)
    }

    @Test
    fun lastEncryptionRound() {
        val state = "0123456789abcdef".toByteArray()

        lastEncryptionRound(state)

        assertArrayEquals(
            byteArrayOf(-49, 124, -52, -27, -71, 20, 120, -120, -71, -126, -10, -96, -32, 97, 33, -27), state
        )
    }

    @Test
    fun undoLastEncryptionRound() {
        val state = byteArrayOf(-49, 124, -52, -27, -71, 20, 120, -120, -71, -126, -10, -96, -32, 97, 33, -27)

        undoLastEncryptionRound(state)

        assertArrayEquals("0123456789abcdef".toByteArray(), state)
    }

    @Test
    fun encryptBlock1() {
        val text = "One nice block!!"

        val encrypted = encryptBlock(text.toByteArray())

        assertEquals("de20759da69aef1a0d2f309a37ac334b", Hex.encodeHexString(encrypted))
    }

    @Test
    fun decryptBlock1() {
        val encrypted = Hex.decodeHex("de20759da69aef1a0d2f309a37ac334b")

        val text = decryptBlock(encrypted)

        assertEquals("One nice block!!", String(text))
    }

    @Test
    fun encryptBlock2() {
        val text = "abcdefghijklmnop"

        val encrypted = encryptBlock(text.toByteArray())

        assertEquals("7ec041d65b2ff88c35b8626d8c2208d2", Hex.encodeHexString(encrypted))
    }

    @Test
    fun decryptBlock2() {
        val encrypted = Hex.decodeHex("7ec041d65b2ff88c35b8626d8c2208d2")

        val text = decryptBlock(encrypted)

        assertEquals("abcdefghijklmnop", String(text))
    }


    @Test
    fun undoXorRound0Step0() {
        val originalIntegers: IntArray = undoXor(0, 0, -1055834467)

        assertArrayEquals(intArrayOf(-559038737, -1445310346, -1267138427, 35639425), originalIntegers)
    }

    @Test
    fun undoXorRound2Step2() {
        val originalIntegers: IntArray = undoXor(2, 2, -2114890313)

        assertArrayEquals(intArrayOf(-777471003, -877095728, -1571472749, 968114193), originalIntegers)
    }

    @Test
    fun decrypt() {
        val encrypted = "9771a6a9aea773a93edc1b9e82b745030b770f8f992d0e45d7404f1d6533f9df348dbccd71034aff88afd188007df4a5c844969584b5ffd6ed2eb92aa419914e"

        decrypt(Hex.decodeHex(encrypted))
    }
}