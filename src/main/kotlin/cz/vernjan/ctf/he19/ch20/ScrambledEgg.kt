package cz.vernjan.ctf.he19.ch20

import cz.vernjan.Resources
import cz.vernjan.saveImageToTemp
import cz.vernjan.showImage
import java.awt.Color
import java.awt.image.BufferedImage
import java.util.function.Predicate

fun main() {
    val scrambledEggImage: BufferedImage = Resources.asImage("he19/ch20/egg.png")
    val rows: List<Row> = readAllRows(scrambledEggImage)

    rows.forEach { it.printAlphaChannel() }

    val unscrambledRows = rows.asSequence()
        .sortedBy { it.sumColorsInAlpha() }
        .drop(1) // Drop the 1st row (RGB 0,0,0) to makes things simpler
        .map { it.shiftColorChannels() }
        .map(Row::toIntArray)
        .toList()

    val unscrambledEggImage: BufferedImage = rowsToImage(unscrambledRows)
    showImage(unscrambledEggImage)
    saveImageToTemp(unscrambledEggImage, "png", "egg-final")
}

fun readAllRows(image: BufferedImage): List<Row> {

    fun readRow(rowIndex: Int): List<Color> = (0 until image.width)
        .map { columnIndex -> image.getRGB(columnIndex, rowIndex) }
        .map { Color(it, true) }

    return (0 until image.height)
        .map { rowIndex -> Row(readRow(rowIndex)) }
}

data class Row(val opaquePixels: List<Color>, val transparentPixels: List<Pair<Int, Color>>) {

    constructor(pixels: List<Color>) : this(
        pixels.filter { it.alpha > 0 },
        pixels.mapIndexed { i, value -> Pair(i, value) }.filter { it.second.alpha == 0 }
    )

    fun printAlphaChannel() {
        val alphaChannel = transparentPixels
            .map { (i, color) -> Pair(i, "Color[r=${color.red},g=${color.green},b=${color.blue},a=${color.alpha}]") }
            .joinToString()
        println(alphaChannel)
    }

    fun sumColorsInAlpha(): Int = transparentPixels
        .map { it.second }
        .map { color -> color.red + color.green + color.blue }
        .sum()

    fun shiftColorChannels(): Row = shiftRed().shiftBlue().shiftGreen()

    private fun shiftRed(): Row {
        return shiftChannel(Predicate { it.red > 0 }) { old, new -> Color(new.red, old.green, old.blue) }
    }

    private fun shiftGreen(): Row {
        return shiftChannel(Predicate { it.green > 0 }) { old, new -> Color(old.red, new.green, old.blue) }
    }

    private fun shiftBlue(): Row {
        return shiftChannel(Predicate { it.blue > 0 }) { old, new -> Color(old.red, old.green, new.blue) }
    }

    private fun shiftChannel(colorSelector: Predicate<Color>, colorCombiner: (old: Color, new: Color) -> Color): Row {
        val shiftSize: Int = getShiftSize(colorSelector)
        val shiftedChannel: List<Color> = shiftChannel(shiftSize)
        return Row(opaquePixels.zip(shiftedChannel, colorCombiner) , transparentPixels)
    }

    private fun getShiftSize(predicate: Predicate<Color>): Int {
        val index = transparentPixels.map { it.second }.indexOfFirst { color -> predicate.test(color) }
        return transparentPixels.first { (_, color) -> predicate.test(color) }.first - index
    }

    private fun shiftChannel(shift: Int): List<Color> {
        return opaquePixels.subList(shift, opaquePixels.size) + opaquePixels.subList(0, shift)
    }

    fun toIntArray() = opaquePixels.map { it.rgb }.toIntArray()
}

private fun rowsToImage(rows: List<IntArray>): BufferedImage {
    val width = rows.first().size
    val image = BufferedImage(width, rows.size, BufferedImage.TYPE_INT_ARGB)

    for (y in (0 until rows.size)) {
        val row = rows[y]
        for (x in (0 until width)) {
            image.setRGB(x, y, row[x])
        }
    }

    return image
}
