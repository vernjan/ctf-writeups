package cz.vernjan.ctf.he21

import cz.vernjan.ctf.Resources
import kotlin.system.exitProcess

val wordlist = Resources.asLines("he21/bip39-list.txt")

//val flagChars = ('0'..'9') + ('a'..'z') + ('A'..'Z') + '_' + '$'
val flagChars = ('0'..'9') + ('a'..'z') + '_' + '!' + '}'
val words = mutableListOf(
    "adapt", "bind", "blind", "craft", "garage", "hip", "home", "hotel", "lonely", "magnet",
    "mushroom", "napkin", "reason", "rescue", "ring", "shift", "small", "sunset", "tongue"
)

fun main() {
//    searchFlags(listOf(FlagContext("he2021{", words)))
    searchFlags(listOf(FlagContext("he2021{", words)))
    exitProcess(1)
}

private fun searchFlags(flagContexts: List<FlagContext>) {
    for (flagContext in flagContexts) {
        val flag = flagContext.flag

//        println("Expanding flag $flag")
//        Thread.sleep(500)

        val newFlags = mutableListOf<FlagContext>()
        val unusedBits = (flag.length * 8) % 11
        if (unusedBits < 3) {
            for (ch1 in flagChars) {
                for (ch2 in flagChars) {
                    val newFlag = testFlag("$flag$ch1$ch2", flagContext.words)
                    if (newFlag != null) {
                        newFlags.add(newFlag)
                    }
                }
            }
        } else {
            for (ch1 in flagChars) {
                val newFlag = testFlag("$flag$ch1", flagContext.words)
                if (newFlag != null) {
                    newFlags.add(newFlag)
                }
            }
        }
        searchFlags(newFlags)
    }
}

private fun testFlag(flag: String, words: List<String>): FlagContext? {
    if (words.isEmpty()) {
        println("No more words left! Flag is: $flag")
        exitProcess(0)
    }

//    println("Testing flag: $flag")

    val indexes = flag.toByteArray()
        .joinToString("") { it.toUByte().toString(2).padStart(8, '0') }
        .chunked(11)
        .map { Integer.valueOf(it, 2) }

    val unusedBits = (flag.length * 8) % 11
    val flagWords = indexes.map { wordlist[it] }
    val newWord = flagWords[if (unusedBits == 0) flagWords.size - 1 else flagWords.size - 2]
    if (words.contains(newWord)) {
        if (words.size == 2) {
//            if (flag.startsWith("he2021{f1sh_")) {

            println("  Possible flag: $flag")
            println("    Words: $flagWords")
            println("    Unused words: $words")
//            }
        }
//        println("    New word: $newWord")
//        println("    Extra bits: $unusedBits")


        return FlagContext(flag, words.minus(newWord))
    }
    return null;
}

class FlagContext(val flag: String, val words: List<String>)