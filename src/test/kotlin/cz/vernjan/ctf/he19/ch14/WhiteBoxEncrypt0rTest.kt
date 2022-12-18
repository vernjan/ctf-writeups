package cz.vernjan.ctf.he19.ch14

import org.apache.commons.codec.binary.Hex
import org.junit.Test

import org.junit.Assert.*

@ExperimentalUnsignedTypes
class WhiteBoxEncrypt0rTest {

    @Test
    fun testShiftRows() {
        val state = "0123456789abcdef".toByteArray()

        Encrypt0r.shiftRows(state)

        assertEquals("01235674ab89fcde", String(state))
    }

    @Test
    fun testBasicEncryptionRound() {
        val state = "abcdefghijklmnop".toByteArray()

        Encrypt0r.basicEncryptionRound(0, state)

        assertArrayEquals(Hex.decodeHex("5002e5ac4b41367fa570630f169d869b"), state)
    }

    @Test
    fun testLastEncryptionRound() {
        val state = "0123456789abcdef".toByteArray()

        Encrypt0r.lastEncryptionRound(state)

        assertArrayEquals(
            byteArrayOf(-49, 124, -52, -27, -71, 20, 120, -120, -71, -126, -10, -96, -32, 97, 33, -27), state
        )
    }
    @Test
    fun testEncryptBlock1() {
        val text = "One nice block!!"

        val encrypted = Encrypt0r.encryptBlock(text.toByteArray())

        assertEquals("de20759da69aef1a0d2f309a37ac334b", Hex.encodeHexString(encrypted))
    }

    @Test
    fun testEncryptBlock2() {
        val text = "abcdefghijklmnop"

        val encrypted = Encrypt0r.encryptBlock(text.toByteArray())

        assertEquals("7ec041d65b2ff88c35b8626d8c2208d2", Hex.encodeHexString(encrypted))
    }

}