package cz.vernjan.ctf.he19.ch11

import java.lang.Exception
import java.net.CookieManager
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.net.http.HttpResponse.BodyHandlers
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executors
import kotlin.streams.asSequence

private const val BASE_URL = "http://whale.hacking-lab.com:1111"

fun main() {
    MemeoryHttpClient(BASE_URL).use { client ->
        client.obtainSession()

        for (i in 1..10) {
            println("Starting round $i")
            playOneRound(client)
        }
    }
}

private fun playOneRound(client: MemeoryHttpClient) {
    val cardsPath = client.downloadAllCardImages()

    // Group cards by file size and play
    Files.list(cardsPath).asSequence()
        .map { Pair(it, Files.size(it)) }
        .groupBy({ it.second }, { it.first.fileName.toString().removeSuffix(".jpg").toInt() })
        .map { Pair(it.value[0], it.value[1]) }
        .map { client.playOneMove(it) }
}

class MemeoryHttpClient(private val url: String) : AutoCloseable {

    private val executorForHttpClient = Executors.newFixedThreadPool(10)

    private val httpClient = HttpClient.newBuilder()
        .cookieHandler(CookieManager())
        .executor(executorForHttpClient)
        .build()

    fun obtainSession() {
        val request = HttpRequest.newBuilder(URI.create(url))
            .GET()
            .timeout(Duration.ofSeconds(5))
            .build()

        val response: HttpResponse<Void> = httpClient.send(request, BodyHandlers.discarding())
        println("Received index with status: ${response.statusCode()}")
    }

    fun downloadAllCardImages(): Path {
        val cardsPath: Path = Files.createTempDirectory("memeory")
        println("New directory for cards images created: $cardsPath")

        // Download in parallel
        val futures = (1..98)
            .map { i -> Pair(i, cardsPath.resolve("$i.jpg")) }
            .map { (i, downloadPath) -> downloadCardImage(i, downloadPath) }
            .toTypedArray()

        CompletableFuture.allOf(*futures).join()

        println("All images downloaded")

        return cardsPath
    }

    private fun downloadCardImage(id: Int, downloadPath: Path): CompletableFuture<Void> {
        val request = HttpRequest.newBuilder()
            .GET()
            .uri(URI.create("$url/pic/$id"))
            .timeout(Duration.ofSeconds(5))
            .build()

        return httpClient.sendAsync(request, BodyHandlers.ofFile(downloadPath))
            .thenAccept { println("${it.statusCode()} ${it.uri()}") }
    }

    fun playOneMove(cards: Pair<Int, Int>) {
        val request = HttpRequest.newBuilder()
            .POST(HttpRequest.BodyPublishers.ofString("first=${cards.first}&second=${cards.second}"))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .uri(URI.create("$url/solve"))
            .timeout(Duration.ofSeconds(5))
            .build()

        try {
            val response = httpClient.send(request, BodyHandlers.ofString())
            println("Play $cards: ${response.statusCode()} ${response.body()}")
        } catch (e: Exception) {
            println("Error: ${e.message}")
            playOneMove(cards)
        }
    }

    override fun close() {
        executorForHttpClient.shutdown()
    }
}