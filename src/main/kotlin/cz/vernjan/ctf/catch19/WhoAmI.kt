package cz.vernjan.ctf.catch19

import java.net.CookieManager
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse.BodyHandlers

val THINGS = mapOf(
    "artificial intelligence" to 1,
    "automatic transmission" to 1,
    "yumy food" to 0,
    "cute kitty" to 0,
    "electric engine" to 1,
    "large hard drive" to 1,
    "lovely puppy" to 0,
    "hope" to 0,
    "love" to 0,
    "fear" to 0,
    "fast CPU" to 1,
    "pretty children" to 0,
    "sweet baby" to 0,
    "drone swarm" to 1,
    "mineral oil" to 1,
    "resistor 10 Ohm" to 1
)

const val CHALLENGE_URL = "http://challenges.thecatch.cz/c2619b989b7ae5eaf6df8047e6893405/"

fun main() {
    val httpClient = HttpClient.newBuilder()
        .cookieHandler(CookieManager())
        .build()

    val requestCaptcha = HttpRequest.newBuilder()
        .GET()
        .uri(URI.create(CHALLENGE_URL)).build()

    val captchaBody = httpClient.send(requestCaptcha, BodyHandlers.ofString()).body()
    println(captchaBody)

    val answer = captchaBody
        .substringAfter('[')
        .substringBefore(']')
        .split(", ")
        .map { THINGS[it] }
        .joinToString(separator = "")

    println("Sending $CHALLENGE_URL?answer=$answer")

    val requestAnswer = HttpRequest.newBuilder()
        .GET()
        .uri(URI.create("$CHALLENGE_URL?answer=$answer")).build()

    val solution = httpClient.send(requestAnswer, BodyHandlers.ofString()).body()
    println(solution)
}
