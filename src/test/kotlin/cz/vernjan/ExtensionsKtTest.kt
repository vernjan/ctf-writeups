package cz.vernjan

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.jupiter.api.Test

class ExtensionsKtTest {

    @Test
    fun byteArrayToHex() {
        assertEquals("48656c6c6f", byteArrayOf(72, 101, 108, 108, 111).toHex())
    }

    @Test
    fun hexToByteArray() {
        assertArrayEquals(byteArrayOf(72, 101, 108, 108, 111), "48656c6c6f".hexToByteArray())
    }

    @Test
    fun asciiToHex() {
        assertEquals("Hello".asciiToHex(), "48656c6c6f")
    }

    @Test
    fun hexToAscii() {
        assertEquals("Hello", "48656c6c6f".hexToAscii())
    }

}

