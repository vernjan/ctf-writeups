package cz.vernjan.he19.ch17

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.util.zip.DataFormatException
import java.util.zip.Deflater
import java.util.zip.Inflater

// TODO to global utils
object CompressionUtils {
    //    private val LOG = Logger.getLogger(CompressionUtils::class.java)
    @Throws(IOException::class)
    fun compress(data: ByteArray): ByteArray {
        val deflater = Deflater()
        deflater.setInput(data)
        val outputStream = ByteArrayOutputStream(data.size)
        deflater.finish()
        val buffer = ByteArray(1024)
        while (!deflater.finished()) {
            val count = deflater.deflate(buffer) // returns the generated code... index
            outputStream.write(buffer, 0, count)
        }
        outputStream.close()
        val output = outputStream.toByteArray()
        println("Original: " + data.size / 1024 + " Kb")
        println("Compressed: " + output.size / 1024 + " Kb")
        return output
    }

    @Throws(IOException::class, DataFormatException::class)
    fun decompress(data: ByteArray): ByteArray {
        val inflater = Inflater()
        inflater.setInput(data)
        val outputStream = ByteArrayOutputStream(data.size)
        val buffer = ByteArray(1024)
        while (!inflater.finished()) {
            val count = inflater.inflate(buffer)
            outputStream.write(buffer, 0, count)
        }
        outputStream.close()
        val output = outputStream.toByteArray()
        println("Original: " + data.size)
        println("Compressed: " + output.size)
        return output
    }
}