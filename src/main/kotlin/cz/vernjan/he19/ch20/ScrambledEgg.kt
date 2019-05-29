package cz.vernjan.he19.ch20

import java.awt.Color
import java.awt.image.BufferedImage
import javax.imageio.ImageIO
import javax.swing.ImageIcon
import javax.swing.JFrame
import javax.swing.JLabel
import javax.swing.WindowConstants

fun main() {
    val imageIn: BufferedImage = ImageIO.read(ImageReader::class.java.getResourceAsStream("egg.png"))
    val imageReader = ImageReader(imageIn)

    val rows: List<Row> = imageReader.readAllRows()

//    rows.forEach { it.printAlpha() }


    val random = rows.random()
    val sortedRows: List<IntArray> = sort(listOf(random), rows.toSet())
        .map(Row::toIntArray)


    val sortedRows2: List<IntArray> = rows
        .sortedBy { it.alphaValue() }
        .map { it.printAlpha2(); it }
        .map(Row::toIntArray)


    val imageOut: BufferedImage = rowsToImage(sortedRows2, imageIn.width)
    showImage(imageOut)
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
            .map { Color(0, it.green, 0) }
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
            .mapIndexed{ i, value -> Pair(i, value) }
            .filter { it.second.alpha == 0}
            .joinToString())
//        println(pixels.map { it.alpha }.joinToString())
    }

    fun printAlpha2() {
        println(pixels
            .mapIndexed{ i, value -> Pair(i, value) }
            .filter { it.second.alpha == 0 }
            .map {
                if (it.second.red != 0) format('R', it.first)
                else if (it.second.green != 0) format('G', it.first)
                else if (it.second.blue != 0) format('B', it.first)
                else "?"
            }
            .joinToString(separator = " "))
//        println(pixels.map { it.alpha }.joinToString())
    }

    fun format(color: Char, position: Int) = position.toString().padStart(3, ' ') + color


    fun alphaValue(): Int = pixels
        .filter { it.alpha == 0}
        .map { it.red + it.green + it.blue }
        .sum()

//    fun sort() {
//        for (i in (0 until pixels.size)){
//            if (pixels[i].alpha == 0 && pixels[i].red != 0) {
//
//            }
//        }
//
//            .
//    }


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
