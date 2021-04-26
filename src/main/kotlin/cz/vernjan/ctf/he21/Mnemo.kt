package cz.vernjan.ctf.he21

import cz.vernjan.ctf.Resources

val list = Resources.asLines("he21/bip39-list.txt")
val chars = ('0'..'9') + ('a'..'z') + ('A'..'Z') + '_' + '$'

fun main() {

    val phrase = mutableListOf(
        "adapt", "bind", "blind", "craft", "garage", "hip", "home", "hotel",
        "lonely", "magnet", "mushroom", "napkin", "reason", "rescue", "ring", "shift", "small", "sunset",
        "tongue"
    )

    val flags = listOf("he2021{", "he2021{f", "he2021{n", "he2021{t")

    flags.forEach { flag ->
        println("Testing flag: $flag")
        val extraBits = (flag.length * 8) % 11
        if (extraBits < 3) {
            for (ch1 in chars) {
                for (ch2 in chars) {
                    doGuess("$flag$ch1$ch2", phrase)
                }
            }
        } else {
            for (ch1 in chars) {
                doGuess("$flag$ch1", phrase)
            }
        }
    }
}

private fun doGuess(
    flag: String,
    phrase: MutableList<String>
) {
//    println("Testing flag: $flag")

    val indexes = flag.toByteArray()
        .joinToString("") { it.toUByte().toString(2).padStart(8, '0') }
        .chunked(11)
        .map { Integer.valueOf(it, 2) }

    val words = indexes.map { list[it] }
    val extraBits = (flag.length * 8) % 11
    val newWord = words[if (extraBits == 0) words.size - 1 else words.size - 2]
    if (phrase.contains(newWord)) {
//        phrase.remove(newWord)
        println("  Possible flag: $flag")
        println("    Words: $words")
        println("    New word: $newWord")
        println("    Extra bits: $extraBits")

    }
}