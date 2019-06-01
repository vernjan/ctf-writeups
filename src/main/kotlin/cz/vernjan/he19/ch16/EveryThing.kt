package cz.vernjan.he19.ch16

import java.nio.file.*
import java.sql.Connection
import java.sql.DriverManager
import java.sql.ResultSet
import java.sql.Statement
import java.util.*

fun main() {

    val query = """
        SELECT t1.type, t1.ord, t1.value AS picName, t2.type, t2.ord, t2.value, t3.type, t3.ord, t3.value
        FROM Thing AS t1
        LEFT JOIN Thing AS t2 ON t2.pid = t1.id
        LEFT JOIN Thing AS t3 ON t3.pid = t2.id
        WHERE t1.type = 'png'
        ORDER BY t1.ord, t2.ord, t3.ord
    """.trimIndent()

    val con: Connection = DriverManager.getConnection("jdbc:mysql://localhost:33060/he19thing", "root", "root")
    val stmt: Statement = con.createStatement()
    val rs: ResultSet = stmt.executeQuery(query)

    var picturePath: Path? = null

    while (rs.next()) {
        val pngChunkType = rs.getString("t2.type")
        if (pngChunkType == "png.head") {
            val pictureName = rs.getString("picName")
            println("Re-building picture: $pictureName")
            picturePath = Paths.get("$pictureName.png")
            Files.createFile(picturePath)
        }

        val value: String = rs.getString("t3.value") ?: rs.getString("t2.value")
        Files.write(picturePath, Base64.getDecoder().decode(value), StandardOpenOption.APPEND)
    }
}