package cz.vernjan.he19.ch20

import java.awt.Color
import java.awt.image.BufferedImage
import javax.imageio.ImageIO
import javax.swing.ImageIcon
import javax.swing.JFrame
import javax.swing.JLabel
import javax.swing.WindowConstants
import java.io.File



fun main() {
    val imageIn: BufferedImage = ImageIO.read(ImageReader::class.java.getResourceAsStream("egg.png"))
    val imageReader = ImageReader(imageIn)

    val rows: List<Row> = imageReader.readAllRows()

//    rows.forEach { it.printAlpha() }


    val random = rows.random()
    val sortedRows: List<IntArray> = sort(listOf(random), rows.toSet())
        .map { it.changeColorSchema() }
        .map(Row::toIntArray)


    val sortedRows2 = rows
        .sortedBy { it.alphaValue() }
//        .map { it.printAlpha2(); it }
        .map { it.changeColorSchema() }
        .map(Row::toIntArray)

//    sortedRows2.forEach { it.printAlpha2() }




    val imageOut: BufferedImage = rowsToImage(sortedRows2, 256)
    showImage(imageOut)

    val outputfile = File("saved.png")
    ImageIO.write(imageOut, "png", outputfile)
}

fun sort(sorted: List<Row>, unsorted: Set<Row>): List<Row> {
    if (unsorted.isEmpty()) return sorted
    val bestMatch = findBestMatch(sorted.last(), unsorted)
    return sort(sorted + bestMatch, unsorted - bestMatch)
}

fun findBestMatch(base: Row, rows: Set<Row>): Row = rows
    .map { row -> Pair(base.diff(row), row) }
    .sortedBy { it.first.total }
    .first().second

//fun findBestMatch2(base: Row, rows: Set<Row>): Row = rows
////    .map { row -> Pair(base.diff(row), row) }
//    .sortedBy { it.alphaValue() }
//    .first()


// TODO refaktor
class ImageReader(private val image: BufferedImage) {

    fun readAllRows(): List<Row> = (0 until image.height)
        .map { i -> Row(readRow(i)) }

    private fun readRow(rowIndex: Int): List<Color> = (0 until image.width)
        .map { columnIndex -> image.getRGB(columnIndex, rowIndex) }
        .map { Color(it, true) }
//        .map { Color(0, it.green, 0) }
}

data class Row(val pixels: List<Color>) {

    private val size = pixels.size

    operator fun get(index: Int) = pixels[index]

    fun diff(other: Row): RowDiff {
        var rowDiff = RowDiff()
        for (i in (0 until size)) {
            val pixelDiff: Color = diffPixels(pixels[i], other[i])
            rowDiff = rowDiff.add(pixelDiff)
        }
        return rowDiff
    }

    // TODO just for fun
//    tailrec fun diffRows2(base: List<Color>, row: List<Color>, rowDiff: RowDiff): RowDiff =
//        diffRows2(base.drop(1), row.drop(1), rowDiff.add(diffPixels(base.first(), row.first())))

    fun printAlpha() {
        println(pixels
            .mapIndexed { i, value -> Pair(i, value) }
            .filter { it.second.alpha == 0 }
            .joinToString())
//        println(pixels.map { it.alpha }.joinToString())
    }

    fun detectColorSchema(): ColorSchema {
        println(pixels)
        var schema = pixels
            .filter { it.alpha == 0 }
            .map {
                when {
                    it.red != 0 -> 'R'
                    it.green != 0 -> 'G'
                    it.blue != 0 -> 'B'
                    else -> '?'
                }
            }
            .joinToString(separator = "")

        if (schema == "???")  schema = "RGB"
        return ColorSchema.valueOf(schema)
    }

    fun changeColorSchema(): Row {
        val schema = detectColorSchema()
        println("Changing schema from $schema")
        return Row(pixels.filter { it.alpha != 0 }.map { schema.convertToRGB(it) })
    }


    fun printAlpha2() {
        println(pixels
            .mapIndexed { i, value -> Pair(i, value) }
            .filter { it.second.alpha == 0 }
            .map {
                if (it.second.red != 0) format('R', it.first)
                else if (it.second.green != 0) format('G', it.first)
                else if (it.second.blue != 0) format('B', it.first)
                else "?"
            }
            .joinToString(separator = " "))
    }

    private fun format(color: Char, position: Int) = position.toString().padStart(3, ' ') + color


    fun alphaValue(): Int = pixels
        .filter { it.alpha == 0 }
        .map { it.red + it.green + it.blue }
        .sum()


    private fun diffPixels(base: Color, pixel: Color): Color {
        val diffR = diffChannels(base.red, pixel.red)
        val diffG = diffChannels(base.green, pixel.green)
        val diffB = diffChannels(base.blue, pixel.blue)
        val diffA = diffChannels(base.alpha, pixel.alpha)
        return Color(diffR, diffG, diffB, diffA)
    }

    private fun diffChannels(base: Int, channel: Int) = Math.abs(base - channel)

    fun toIntArray() = pixels.map { it.rgb }.toIntArray()
}

enum class ColorSchema {
    RGB, RBG, GBR, GRB, BGR, BRG;

    fun convertToRGB(color: Color): Color = when (this) {
        RGB -> Color(color.red, color.green, color.blue, color.alpha)
        RBG -> Color(color.red, color.blue, color.green, color.alpha)
        GBR -> Color(color.green, color.blue, color.red, color.alpha)
        GRB -> Color(color.green, color.red, color.blue, color.alpha)
        BGR -> Color(color.blue, color.green, color.red, color.alpha)
        BRG -> Color(color.blue, color.red, color.green, color.alpha)
    }
}

data class RowDiff(
    val diffR: Int = 0,
    val diffG: Int = 0,
    val diffB: Int = 0,
    val diffA: Int = 0
) {
    val total = diffR + diffG + diffB

    fun add(color: Color) = RowDiff(
        diffR + color.red,
        diffG + color.green,
        diffB + color.blue,
        diffA + color.alpha
    )
}


private fun rowsToImage(rows: List<IntArray>, width: Int): BufferedImage {
    val image = BufferedImage(width, rows.size, BufferedImage.TYPE_INT_ARGB)

    for (y in (0 until rows.size)) {
        val row = rows[y]
        for (x in (0 until width)) {
            image.setRGB(x, y, row[x])
        }
    }

    return image
}

private fun showImage(image: BufferedImage) {
    val frame = JFrame()
    frame.defaultCloseOperation = WindowConstants.EXIT_ON_CLOSE
    frame.setLocationRelativeTo(null)
    frame.setSize(image.width + 100, image.height + 100)
    frame.add(JLabel(ImageIcon(image)))
    frame.isVisible = true
}
