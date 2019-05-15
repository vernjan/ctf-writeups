package cz.vernjan.he19.ch14

import org.apache.commons.codec.binary.Hex
import org.junit.Test

import org.junit.Assert.*

class WhiteBoxKtTest {

    @Test
    fun copyAndSwap() {
        val source: ByteArray = "0123456789abcdef".toByteArray()

        assertEquals("048c159d26ae37bf", String(copyAndSwap(source)))
    }

    @Test
    fun copyAndReverseSwap() {
        val source: ByteArray = "048c159d26ae37bf".toByteArray()

        assertEquals("0123456789abcdef", String(copyAndSwap(source)))
    }


    @Test
    fun shiftRows() {
        val source: ByteArray = "0123456789abcdef".toByteArray()

        assertEquals("01237456ab89defc", String(shiftRows(source)))
    }

    @Test
    fun encryptBlock() {
        val text = "One nice block!!"

        val encrypted: ByteArray = encryptBlock(text.toByteArray())

        assertEquals("de20759da69aef1a0d2f309a37ac334b67160e5673ae393ce6c5fb77a8d7eb44", Hex.encodeHexString(encrypted))
    }

    @Test
    fun encryptBlock2() {
        val text = "One nice block!"

        val encrypted: ByteArray = encryptBlock(text.toByteArray())

        assertEquals("a20cfb16a3482d71bc96fec97bebaf62", Hex.encodeHexString(encrypted))
    }
}