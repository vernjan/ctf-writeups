package cz.vernjan.ctf.he19.ch14

import org.junit.Assert.assertEquals
import org.junit.Test

class WhiteBoxTest {

    @Test
    fun testSwapRowsWithColumns() {
        val state = "0123456789abcdef".toByteArray()

        swapRowsWithColumns(state)

        assertEquals("048c159d26ae37bf", String(state))
    }

}