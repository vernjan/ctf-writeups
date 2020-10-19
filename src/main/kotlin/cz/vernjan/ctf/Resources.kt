package cz.vernjan.ctf

import java.awt.image.BufferedImage
import java.io.InputStream
import java.io.InputStreamReader
import java.io.Reader
import javax.imageio.ImageIO

object Resources {

    fun asString(path: String): String = String(asBytes(path))
    fun asLines(path: String): List<String> = asString(path).lines()
    fun asBytes(path: String): ByteArray = asStream(path).readAllBytes()
    fun asImage(path: String): BufferedImage = ImageIO.read(asStream(path))
    fun asReader(path: String): Reader = InputStreamReader(asStream(path))
    fun asStream(path: String): InputStream = Resources::class.java.getResourceAsStream(path)

}