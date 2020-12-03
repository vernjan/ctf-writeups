package cz.vernjan.ctf

import java.awt.Color
import java.awt.image.BufferedImage
import javax.swing.ImageIcon
import javax.swing.JFrame
import javax.swing.JLabel

class QRCode(val data: Array<BooleanArray>) {

    companion object {
        fun fromImage(qr: BufferedImage, squareSizeInPixels: Int, margin: Int = 0): QRCode {
            val data: Array<BooleanArray> = (margin until (qr.height - margin) step squareSizeInPixels).map { y ->
                (margin until (qr.width - margin) step squareSizeInPixels)
                    .map { x -> qr.getRGB(x, y) }
                    .map { Color(it) == Color.BLACK }
                    .toBooleanArray()
            }.toTypedArray()

            return QRCode(data)
        }
    }

    val width = data.size

    fun printASCII() {
        data.forEach { row ->
            println(row.joinToString(separator = "") { if (it) "#" else " " })
        }
    }

    fun render() {
        val image = BufferedImage(
            width,
            width,
            BufferedImage.TYPE_INT_RGB
        )
        for (x in 0 until width) {
            for (y in 0 until width) {
                image.setRGB(x, y, (if (data[y][x]) Color.BLACK else Color.WHITE).rgb)
            }
        }

        val frame = JFrame()
        frame.setLocationRelativeTo(null)
        frame.isVisible = true
        frame.defaultCloseOperation = JFrame.EXIT_ON_CLOSE
        frame.add(JLabel(ImageIcon(image)))
        frame.pack()
    }

}