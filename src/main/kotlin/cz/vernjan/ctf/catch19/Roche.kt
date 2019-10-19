package cz.vernjan.ctf.catch19

import cz.vernjan.ctf.hexToAscii
import cz.vernjan.ctf.hexToByteArray
import okhttp3.Headers
import java.lang.StringBuilder
import java.net.CookieManager
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpRequest.*
import java.net.http.HttpResponse
import java.net.http.HttpResponse.*
import kotlin.experimental.xor
import kotlin.system.exitProcess

private val ciphertext =
    "463216327617246f67406f1266075ec622606c6671765537066636596e621e64e622c2b006066961c66e621f067676e77c6e665167a462c4b50477433617754222d7043542885747df6dd575970417d435223000"
private val keys = listOf(
    "5%3B4%3B1%3B3%3B2%3B6",
    "6%3B5%3B3%3B4%3B1%3B2%3B7",
    "7%3B6%3B2%3B4%3B5%3B1%3B3%3B8",
    "2%3B7%3B6%3B5%3B1%3B3%3B4%3B8",
    "5%3B4%3B3%3B1%3B2%3B6"
)

fun main() {

    val httpClient = HttpClient.newBuilder().build()

    for (key1 in keys) {
        for (key2 in keys) {
            println("Keys: $key1, $key2")

            // 1 c l
            // 2 l c
            // 3 c c
            val body =
                "tool=double-transposition-cipher&ciphertext=$ciphertext&permutation1=$key1&permute1=l&permutation2=$key2&permute2=l"

            val request = newBuilder()
                .POST(BodyPublishers.ofString(body))
                .uri(URI.create("https://www.dcode.fr/api/"))
                .header("content-type", "application/x-www-form-urlencoded; charset=UTF-8")
                .build()

            val response = httpClient.send(request, BodyHandlers.ofString())
            if (response.statusCode() == 200) {
                val result = response.body()!!.split('"')[3]
                println(response)
                println(result)
                println(result.hexToAscii())
                if (result.hexToAscii().contains("FLAG")) {
                    println("BINGO!")
                    exitProcess(0)
                }
            }
//            println(response.hexToAscii())
        }
    }
}