package cz.vernjan

import java.awt.image.BufferedImage
import java.io.File
import java.nio.file.Files
import java.nio.file.Paths
import javax.imageio.ImageIO
import javax.swing.ImageIcon
import javax.swing.JFrame
import javax.swing.JLabel
import javax.swing.WindowConstants

// TODO Refactor this!
fun String.hexToAscii(): String {
    val output = StringBuilder()

    for (i in 0..(length - 2) step 2) {
        val str = substring(i, i + 2)
        output.append(Integer.parseInt(str, 16).toChar())
    }

    return output.toString()
}

fun String.asciiToHex(): String = toCharArray().joinToString { Integer.toHexString(it.toInt()) }

fun Int.toAscii() = Integer.toHexString(this).hexToAscii()
fun Int.toHex() = Integer.toHexString(this).padStart(8, '0')

fun readFile(path: String): String = Files.readString(Paths.get("src/main/kotlin/cz/vernjan/he19/$path"))
//fun readAllBytes(path: String): ByteArray = Files.readAllBytes(Paths.get("src/main/resources/cz/vernjan/he19/$path"))
fun readTestFile(path: String): String = Files.readString(Paths.get("src/test/kotlin/cz/vernjan/he19/$path"))

// TODO names
object Resources {
    // TODO byte array
    fun foo(path: String) = Resources::class.java.getResourceAsStream(path)
    fun loadImage(path: String): BufferedImage = ImageIO.read(foo(path))
    fun saveImage(image: BufferedImage, format: String, path: String): Boolean = ImageIO.write( // TODO .. To src/rsources
        image, format, Paths.get("src/main/kotlin/cz/vernjan", path).toFile())
}

// TODO Ext. function
fun showImage(image: BufferedImage) {
    val frame = JFrame()
    frame.defaultCloseOperation = WindowConstants.EXIT_ON_CLOSE
    frame.setLocationRelativeTo(null)
    frame.setSize(image.width + 100, image.height + 100)
    frame.add(JLabel(ImageIcon(image)))
    frame.isVisible = true
}