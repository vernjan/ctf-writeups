package cz.vernjan

import java.awt.image.BufferedImage
import java.nio.file.Files
import javax.imageio.ImageIO
import javax.swing.ImageIcon
import javax.swing.JFrame
import javax.swing.JLabel
import javax.swing.WindowConstants

fun showImage(image: BufferedImage) {
    val frame = JFrame()
    frame.defaultCloseOperation = WindowConstants.EXIT_ON_CLOSE
    frame.setLocationRelativeTo(null)
    frame.setSize(image.width + 50, image.height + 50)
    frame.add(JLabel(ImageIcon(image)))
    frame.isVisible = true
}

fun saveImageToTemp(image: BufferedImage, format: String, name: String) {
    val path = Files.createTempFile("${name}_", ".$format")
    println("Saving image to $path")
    ImageIO.write(image, format, path.toFile())
}