package cz.vernjan.ctf.he19.ch14

import cz.vernjan.ctf.hexToByteArray
import org.apache.commons.codec.binary.Hex
import org.junit.Test

import org.junit.Assert.*

@ExperimentalUnsignedTypes
class WhiteBoxDecrypt0rTest {

    @Test
    fun testUndoShiftRows() {
        val state = "01235674ab89fcde".toByteArray()

        Decrypt0r.undoShiftRows(state)

        assertEquals("0123456789abcdef", String(state))
    }

    @Test
    fun testUndoBasicEncryptionRound() {
        val state = Hex.decodeHex("5002e5ac4b41367fa570630f169d869b")

        Decrypt0r.undoBasicEncryptionRound(0, state)

        assertArrayEquals("abcdefghijklmnop".toByteArray(), state)
    }

    @Test
    fun testUndoLastEncryptionRound() {
        val state = byteArrayOf(-49, 124, -52, -27, -71, 20, 120, -120, -71, -126, -10, -96, -32, 97, 33, -27)

        Decrypt0r.undoLastEncryptionRound(state)

        assertArrayEquals("0123456789abcdef".toByteArray(), state)
    }

    @Test
    fun testDecryptBlock1() {
        val encrypted = Hex.decodeHex("de20759da69aef1a0d2f309a37ac334b")

        val text = Decrypt0r.decryptBlock(encrypted)

        assertEquals("One nice block!!", String(text))
    }

    @Test
    fun testDecryptBlock2() {
        val encrypted = Hex.decodeHex("7ec041d65b2ff88c35b8626d8c2208d2")

        val text = Decrypt0r.decryptBlock(encrypted)

        assertEquals("abcdefghijklmnop", String(text))
    }

    @Test
    fun testUndoXorRound0Step0() {
        val originalIntegers: IntArray = Decrypt0r.undoXor(0, 0, -1055834467)

        assertArrayEquals(intArrayOf(-559038737, -1445310346, -1267138427, 35639425), originalIntegers)
    }

    @Test
    fun testUndoXorRound2Step2() {
        val originalIntegers: IntArray = Decrypt0r.undoXor(2, 2, -2114890313)

        assertArrayEquals(intArrayOf(-777471003, -877095728, -1571472749, 968114193), originalIntegers)
    }

    @Test
    fun testDecrypt() {
        val encrypted = "9771a6a9aea773a93edc1b9e82b745030b770f8f992d0e45d7404f1d6533f9df" +
                    "348dbccd71034aff88afd188007df4a5c844969584b5ffd6ed2eb92aa419914e"

        Decrypt0r.decrypt(encrypted.hexToByteArray())
    }

}