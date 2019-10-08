package cz.vernjan.ctf.catch19

import java.net.CookieManager
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse.BodyHandlers

private const val CHALLENGE_URL = "http://challenges.thecatch.cz/70af21e71285ab0bc894ef84b6692ae1/"

fun main() {
    val httpClient = HttpClient.newBuilder()
        .cookieHandler(CookieManager())
        .build()

    val requestCaptcha = HttpRequest.newBuilder()
        .GET()
        .uri(URI.create(CHALLENGE_URL)).build()

    val captchaBody = httpClient.send(requestCaptcha, BodyHandlers.ofString()).body()
    println(captchaBody)

    val equationStr = captchaBody
        .substringAfter("equation ")
        .substringBefore(",")

    println(equationStr)

    val (var1, var2) = captchaBody
        .substringAfter("where ")
        .substringBefore("\n")
        .split(", ")

    val equation = Equation(equationStr)
        .substituteVariable(Variable.parse(var1))
        .substituteVariable(Variable.parse(var2))

    println(equation)

    // TODO https://www.mathpapa.com/equation-solver/
    val answer = 42000

    println("Sending $CHALLENGE_URL?answer=$answer")

    val requestAnswer = HttpRequest.newBuilder()
        .GET()
        .uri(URI.create("$CHALLENGE_URL?answer=$answer")).build()

    val solution = httpClient.send(requestAnswer, BodyHandlers.ofString()).body()
    println(solution)
}

private data class Equation(val equation: String) {
    fun substituteVariable(variable: Variable): Equation {
        println("Substituting $variable")
        return Equation(equation.replace(variable.name, "*${variable.value}"))
    }
}

private data class Variable(val name: String, val value: Int) {
    companion object {
        fun parse(variable: String): Variable {
            val (name, value) = variable.split(" = ")
            return Variable(name, value.toInt())
        }
    }
}