package cz.vernjan.ctf.hv19.day09

import cz.vernjan.ctf.Resources
import java.awt.Color
import java.awt.image.BufferedImage
import javax.swing.ImageIcon
import javax.swing.JFrame
import javax.swing.JLabel


val SQUARE_SIZE = 5


class QRCode(qr: BufferedImage, squareSizeInPixels: Int) {

    val data: Array<BooleanArray> = readQRCode(qr, squareSizeInPixels)

    val width = data[0].size
    val height = data.size

    fun printASCII() {
        data.forEach { line ->
            println(line.joinToString(separator = "") { if (it) "#" else " " })
        }
    }

    fun render() {
        val image = BufferedImage(width, height, BufferedImage.TYPE_INT_RGB)
        for (x in 0 until width) {
            for (y in 0 until height) {
                image.setRGB(x, y, (if (data[y][x]) Color.BLACK else Color.WHITE).rgb)
            }
        }

        val frame = JFrame()
        frame.setLocationRelativeTo(null)
        frame.isVisible = true
        frame.defaultCloseOperation = JFrame.EXIT_ON_CLOSE;
        frame.add(JLabel(ImageIcon(image)))
        frame.pack()
    }

    private fun readQRCode(qr: BufferedImage, squareSizeInPixels: Int): Array<BooleanArray> {
        return (0 until qr.height step squareSizeInPixels).map { y ->
            (0 until qr.width step squareSizeInPixels)
                .map { x -> qr.getRGB(x, y) }
                .map { Color(it) == Color.BLACK }
                .toBooleanArray()
        }.toTypedArray()
    }

}

// TODO line vs row

// TODO to library
fun main() {
    val codeImage: BufferedImage = Resources.asImage("hv19/day09/barcode.png")
    val qrCode = QRCode(codeImage, 5)


    val rule30 = rule30(33)





    qrCode.data.forEachIndexed { rowIndex, row ->
        val ruleSize = rule30[rowIndex].size
        println("Rule size $ruleSize")
        val startIndex = ((33 - ruleSize) / 2) + 1 // Fucking shift by one
        val stopIndex = startIndex + ruleSize
        println("startIndex $startIndex, stopIndex $stopIndex")

        row.forEachIndexed { colIndex, col ->
            if (colIndex in startIndex until stopIndex) {

                qrCode.data[rowIndex][colIndex] = qrCode.data[rowIndex][colIndex] xor rule30[rowIndex][colIndex - startIndex]
            }

            // TODO shift by 1 right !!

        }
    }

    qrCode.render()

}


fun rule30(steps: Int): List<List<Boolean>> {
    val data: MutableList<List<Boolean>> = mutableListOf()
    var step: List<Boolean> = listOf(true)
    data.add(step)

    var i = 1
    while (i++ < steps) {
        println("Step $i")
        step = nextStep(step)
        println(step)
        data.add(step)
    }

    return data
}

fun nextStep(currentStep: List<Boolean>): List<Boolean> { // TODO list better I guess
    val nextStep = currentStep.toMutableList()
    nextStep.add(0, false)
    nextStep.add(false)

    return nextStep.mapIndexed { index, _ ->
        rule30(nextStep, index)
    }.toList()
}

fun rule30(line: List<Boolean>, current: Int): Boolean {
    val left = line.getOrNull(current - 1) ?: false
    val middle = line[current]
    val right = line.getOrNull(current + 1) ?: false

    val res = when {
        left && middle && right -> false
        left && middle && !right -> false
        left && !middle && right -> false
        left && !middle && !right -> true
        !left && middle && right -> true
        !left && middle && !right -> true
        !left && !middle && right -> true
        !left && !middle && !right -> false
        else -> throw RuntimeException("Impossible")
    }
    return res
}

