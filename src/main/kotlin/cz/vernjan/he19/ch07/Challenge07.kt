package cz.vernjan.he19.ch07

import cz.vernjan.he19.readFile

fun main() {
    val replacements = readFile("ch07/replacements.txt")
    val obfuscated: String = readFile("ch07/obfuscated.txt")

    var plain = obfuscated

    replacements.split("\n")
            .map { it.split("=".toRegex(), 2) }
            .map { Pair(it[0], it[1]) }
            .map { Pair("\\\$${it.first}", it.second.substring(1, it.second.length - 1)) }
            .forEach {
                println("Replacing ${it.first} with ${it.second}")
                plain = plain
                        .replace(it.first.toRegex(), Regex.escapeReplacement(it.second))
                        .replace("\\\\n".toRegex(), "\n")
            }

    println(plain)
}
