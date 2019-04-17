package cz.vernjan.he19.ch00_teaser

import java.awt.image.BufferedImage
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import javax.imageio.ImageIO
import javax.swing.ImageIcon
import javax.swing.JFrame
import javax.swing.JLabel
import javax.swing.WindowConstants

private const val WIDTH = 480
private const val HEIGHT = 480

fun main() {
    val pathToImages = Paths.get("""d:\Shared\HE19\Teaser""")

    val pixelsIn: IntArray = Files.list(pathToImages)
            .filter { it.toString().endsWith("jpg") }
            .mapToInt { getPixelColor(it) }
            .toArray()

    val imageOut = BufferedImage(WIDTH, HEIGHT, BufferedImage.TYPE_3BYTE_BGR)
    imageOut.setRGB(0, 0, WIDTH, HEIGHT, pixelsIn, 0, WIDTH)
    showImage(imageOut)
}

private fun getPixelColor(path: Path): Int = ImageIO.read(path.toFile()).getRGB(0, 0)

private fun showImage(image: BufferedImage) {
    val frame = JFrame()
    frame.defaultCloseOperation = WindowConstants.EXIT_ON_CLOSE
    frame.setLocationRelativeTo(null)
    frame.setSize(image.width, image.height)
    frame.add(JLabel(ImageIcon(image)))
    frame.isVisible = true
}