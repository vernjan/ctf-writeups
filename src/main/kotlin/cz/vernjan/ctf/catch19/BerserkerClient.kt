package cz.vernjan.ctf.catch19

import java.net.CookieManager
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse.*

class BerserkerClient(challengePath: String) {
    private val challengeUrl = "http://challenges.thecatch.cz/$challengePath/"

    private val httpClient = HttpClient.newBuilder()
        .cookieHandler(CookieManager())
        .build()

    fun fetchAssignment(): String {
        val request = HttpRequest.newBuilder()
            .GET()
            .uri(URI.create(challengeUrl)).build()

        val assignment = httpClient.send(request, BodyHandlers.ofString()).body()!!
        println(assignment)
        return assignment
    }

    fun sendAnswer(answer: String) {
        println("Sending $challengeUrl?answer=$answer")

        val request = HttpRequest.newBuilder()
            .GET()
            .uri(URI.create("$challengeUrl?answer=$answer")).build()

        val flag = httpClient.send(request, BodyHandlers.ofString()).body()
        println(flag)
    }
}