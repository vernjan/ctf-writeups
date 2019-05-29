package cz.vernjan.he19.ch20

import org.junit.Test

import java.awt.Color
import kotlin.test.assertEquals

class ColorSchemaTest {

    @Test
    fun convertFromBGR() {
        val color = Color(1,2,3)
        val converted = ColorSchema.BGR.convertToRGB(color)
        assertEquals(Color(3,2,1), converted)
    }

    @Test
    fun convertFromRGB() {
        val color = Color(1,2,3)
        val converted = ColorSchema.RGB.convertToRGB(color)
        assertEquals(color, converted)
    }

    @Test
    fun convertFromGBR() {
        val color = Color(1,2,3)
        val converted = ColorSchema.GBR.convertToRGB(color)
        assertEquals(Color(2, 3, 1), converted)
    }
}