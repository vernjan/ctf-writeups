package cz.vernjan

import java.awt.image.BufferedImage
import java.io.InputStream
import javax.imageio.ImageIO

object Resources {

    fun asStream(path: String): InputStream = Resources::class.java.getResourceAsStream(path)
    fun asBytes(path: String): ByteArray = asStream(path).readAllBytes()
    fun asString(path: String): String = String(asBytes(path))
    fun asImage(path: String): BufferedImage = ImageIO.read(asStream(path))

}