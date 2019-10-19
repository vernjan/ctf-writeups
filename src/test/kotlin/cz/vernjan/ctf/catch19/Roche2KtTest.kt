package cz.vernjan.ctf.catch19

import cz.vernjan.ctf.catch19.Mode.*
import org.junit.Assert.*
import org.junit.jupiter.api.Test

private val data = "abcde12345efghi67890"
private val key = intArrayOf(4, 3, 2, 1, 0)

class Roche2KtTest {

    @Test
    fun `encrypt then read by lines`() {
        val encrypted = transpose(data, key, mode = ENCRYPT_READ_LINES)

        assertEquals("edcba54321ihgfe09876", encrypted)
    }

    @Test
    fun `encrypt then read by columns`() {
        val encrypted = transpose(data, key, mode = ENCRYPT_READ_COLUMNS)

        assertEquals("e5i0d4h9c3g8b2f7a1e6", encrypted)
    }

    @Test
    fun `decrypt from lines`() {
        val decrypted = transpose("edcba54321ihgfe09876", key, mode = DECRYPT_FROM_LINES)

        assertEquals(data, decrypted)
    }

    @Test
    fun `decrypt from columns`() {
        val decrypted = transpose("e5i0d4h9c3g8b2f7a1e6", key, mode = DECRYPT_FROM_COLUMNS)

        assertEquals(data, decrypted)
    }
}