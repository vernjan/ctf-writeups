package cz.vernjan.ctf.catch19

import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpRequest.*
import java.net.http.HttpResponse.BodyHandlers

fun main() {
    val client = BerserkerClient("70af21e71285ab0bc894ef84b6692ae1")
    val assignment = client.fetchAssignment()

    val unknownVar = assignment.substringAfter("'").substringBefore("'")
    println("Unknown variable is: $unknownVar")

    val (var1, var2) = assignment
        .substringAfter("where ")
        .substringBefore("\n")
        .split(", ")

    val equation: String = Equation(parseEquation(assignment))
        .substituteVariable(Variable.parse(var1))
        .substituteVariable(Variable.parse(var2)).asString()
    println(equation)

    val answer = solveEquation(equation, unknownVar)

    client.sendAnswer(answer)
}

private fun parseEquation(assignment: String) = assignment
    .substringAfter("equation ")
    .substringBefore(",")

private fun solveEquation(equation: String, unknownVar: String): String {
    val equationPayload =
        "cmd=solve_stepssolveequation&expression=${URLEncoder.encode(equation, "UTF-8")}&variables=$unknownVar"
    println(equationPayload)

    val requestEquationCalculation = newBuilder()
        .POST(BodyPublishers.ofString(equationPayload))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .uri(URI.create("https://quickmath.com/msolver/apply_cmd.php")).build()

    val equationSolution = HttpClient.newHttpClient().send(requestEquationCalculation, BodyHandlers.ofString()).body()
    println(equationSolution)
    return equationSolution.substringAfter("$unknownVar=").substringBefore("-")
}

private data class Equation(private val equation: String) {
    fun substituteVariable(variable: Variable): Equation {
        println("Substituting $variable")
        return Equation(equation.replace(variable.name, "*${variable.value}"))
    }

    fun asString() = equation
}

private data class Variable(val name: String, val value: Int) {
    companion object {
        fun parse(variable: String): Variable {
            val (name, value) = variable.split(" = ")
            return Variable(name, value.toInt())
        }
    }
}