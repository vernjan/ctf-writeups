package cz.vernjan.ctf.he21

import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse

fun main() {
    val egg = "41E5D00E5CECC3019834C99B403DE4B24933AF3087BCE219699D7E3EB178A06F7B4717A36C617760EC0AD8BFD5DF05B2"
    val httpClient = HttpClient.newHttpClient()

    for (i in 0 until 32 step 2) {
        val b = egg.substring(i, i + 2)
        val fuzz = if (b == "00") "ff" else "00"
        val code = egg.substring(0, i) + fuzz + egg.substring(i + 2)
        println("Byte position ${i / 2}: ($b --> $fuzz)")

        val request = HttpRequest.newBuilder()
            .GET()
            .uri(URI.create("http://46.101.107.117:2110/picture?code=$code")).build()

        val response = httpClient.send(request, HttpResponse.BodyHandlers.ofString()).body()!!
        response.lines().filter { it.contains("<span>") }.forEach { println(it) }
    }
}
