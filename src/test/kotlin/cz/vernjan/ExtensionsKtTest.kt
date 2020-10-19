package cz.vernjan

import cz.vernjan.ctf.*
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

    @Test
    fun intToHex() {
        assertEquals("1000", 4096.toHex())
    }

    @Test
    fun hexToInt() {
        assertEquals(4096, "1000".hexToInt())
    }

    @Test
    fun decodeBase64() {
        assertEquals("Hello", "SGVsbG8=".decodeBase64())
    }

    @Test
    fun encodeBase64() {
        assertEquals("SGVsbG8=", "Hello".encodeBase64())
    }

    @Test
    fun hexToBase64() {
        assertEquals("SGVsbG8=", "48656c6c6f".hexToBase64())
    }

    @Test
    fun base64ToHex() {
        assertEquals("48656c6c6f", "SGVsbG8=".base64ToHex())
    }

    @Test
    fun rot13LowerCase() {
        assertEquals("nom", "abz".rot13())
    }

    @Test
    fun rot13UpperCase() {
        assertEquals("NOM", "ABZ".rot13())
    }

    @Test
    fun rot13AllChars() {
        assertEquals("[nN1-mM2]", "[aA1-zZ2]".rot13())
    }
}

