package cz.vernjan.teaser

import java.awt.image.BufferedImage
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import javax.imageio.ImageIO
import javax.swing.ImageIcon
import javax.swing.JFrame
import javax.swing.JLabel
import javax.swing.WindowConstants

// Step 1) Run ffmpeg -i he2019_teaser.mp4 -s 1x1 $pic%06d.jpg
// Step 2) Run this program

private const val WIDTH = 480
private const val HEIGHT = 480

object Teaser {

    @JvmStatic
    fun main(args: Array<String>) {
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
}