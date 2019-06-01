package cz.vernjan.ctf.he19.ch15

import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpRequest.BodyPublishers
import java.net.http.HttpResponse.BodyHandlers
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executors

fun main() {
    SteemApiClient().use {
        client -> downloadAllBlocks(client)
    }
}

fun downloadAllBlocks(client: SteemApiClient) {
    val blocksPath: Path = Files.createTempDirectory("steem")
    println("New directory for blocks created: $blocksPath")

    val futures = (21179363..21_200_000)
            .map { blockId -> Pair(blockId, blocksPath.resolve("$blockId.json")) }
            .map { (blockId, downloadPath) -> client.downloadBlock(blockId, downloadPath) }
            .toTypedArray()

    CompletableFuture.allOf(*futures).join()
}

class SteemApiClient : AutoCloseable {

    private val executorForHttpClient = Executors.newFixedThreadPool(10)

    private val httpClient = HttpClient.newBuilder()
            .executor(executorForHttpClient)
            .build()

    fun downloadBlock(blockId: Int, downloadPath: Path): CompletableFuture<Void> {
        val request = HttpRequest.newBuilder()
                .POST(BodyPublishers.ofString(
                        """{"id":4,"jsonrpc":"2.0","method":"call","params":["database_api","get_block",[$blockId]]}"""))
                .header("Content-Type", "application/json")
                .uri(URI.create("https://api.steemit.com/"))
                .timeout(Duration.ofSeconds(60))
                .build()

        Thread.sleep(200)

        return httpClient.sendAsync(request, BodyHandlers.ofFile(downloadPath))
                .thenAccept { println("${it.statusCode()} ${it.body()}") }
    }

    override fun close() {
        executorForHttpClient.shutdown()
    }
}
