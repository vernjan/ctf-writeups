package cz.vernjan.ctf.catch19

import org.junit.Assert.assertEquals
import org.junit.jupiter.api.Test

private val plaintext = "abcde12345efghi67890"
private val key53412 = key(5, 3, 4, 1, 2)

class RocheKtTest {

    @Test
    fun `transpose columns then read by rows`() {
        assertEquals("debca45231hifge90786", transposeColumns(plaintext, key53412).readByRows())
    }

    @Test
    fun `transpose columns then read by columns`() {
        assertEquals("d4h9e5i0b2f7c3g8a1e6", transposeColumns(plaintext, key53412).readByColumns())
    }

    @Test
    fun `transpose rows then read by rows`() {
        assertEquals("ghi67890e12345efabcd", transposeRows(plaintext, key53412).readByRows())
    }

    @Test
    fun `transpose rows then read by columns`() {
        assertEquals("g7e4ah815bi92ec603fd", transposeRows(plaintext, key53412).readByColumns())
    }


    @Test
    fun `revert transposed columns read by rows`() {
        val encrypted = transposeColumns(plaintext, key53412).readByRows()
        assertEquals("debca45231hifge90786", encrypted)
        val decrypted = transposeColumns(encrypted, invertKey(key53412)).readByRows()

        assertEquals(plaintext, decrypted)
    }

    @Test
    fun `revert transposed columns read by columns`() {
        val encrypted = transposeColumns(plaintext, key53412).readByColumns()
        assertEquals("d4h9e5i0b2f7c3g8a1e6", encrypted)
        val decrypted = transposeRows(encrypted, invertKey(key53412)).readByColumns()

        assertEquals(plaintext, decrypted)
    }

    @Test
    fun `revert transposed rows read by rows`() {
        val encrypted = transposeRows(plaintext, key53412).readByRows()
        assertEquals("ghi67890e12345efabcd", encrypted)
        val decrypted = transposeRows(encrypted, invertKey(key53412)).readByRows()

        assertEquals(plaintext, decrypted)
    }

    @Test
    fun `revert transposed rows read by columns`() {
        val encrypted = transposeRows(plaintext, key53412).readByColumns()
        assertEquals("g7e4ah815bi92ec603fd", encrypted)
        val decrypted = transposeColumns(encrypted, invertKey(key53412)).readByColumns()

        assertEquals(plaintext, decrypted)
    }

    // TODO test with Donder, Blitzen ..

}