package cz.vernjan.ctf.he21

import com.google.common.hash.Hashing
import cz.vernjan.ctf.Resources
import cz.vernjan.ctf.toBinary

val wordlist = Resources.asLines("he21/bip39-list.txt")
val flagChars = ('0'..'9') + ('a'..'z') + '_' + '!' + '}'
val words = mutableListOf(
    "adapt", "bind", "blind", "craft", "garage", "hip", "home", "hotel", "lonely", "magnet",
    "mushroom", "napkin", "reason", "rescue", "ring", "shift", "small", "sunset", "tongue"
)

fun main() {
    searchFlags(listOf(FlagContext("he2021{", words)))
}

private fun searchFlags(flagContexts: List<FlagContext>) {
    for (flagContext in flagContexts) {
        val flag = flagContext.flag
        val newFlagContexts = mutableListOf<FlagContext>()

        val remainingBitsCount = (flag.length * 8) % 11
        if (remainingBitsCount < 3) {
            for (ch1 in flagChars) {
                for (ch2 in flagChars) {
                    val newFlagContext = evaluateFlag("$flag$ch1$ch2", flagContext.words)
                    if (newFlagContext != null) {
                        newFlagContexts.add(newFlagContext)
                    }
                }
            }
        } else {
            for (ch1 in flagChars) {
                val newFlagContext = evaluateFlag("$flag$ch1", flagContext.words)
                if (newFlagContext != null) {
                    newFlagContexts.add(newFlagContext)
                }
            }
        }
        searchFlags(newFlagContexts)
    }
}

private fun evaluateFlag(flag: String, remainingWords: List<String>): FlagContext? {
    val flagWords = flag.toByteArray()
        .joinToString("") { it.toBinary() }
        .chunked(11)
        .map { Integer.valueOf(it, 2) }.map { wordlist[it] }

    val remainingBitsCount = (flag.length * 8) % 11
    val newWord = flagWords[flagWords.size - if (remainingBitsCount == 0) 1 else 2]
    if (remainingWords.contains(newWord)) {
        if (flag.length == 32 && flag.endsWith("}")) {
            val checksumWord = getChecksumWord(flag, remainingBitsCount)
            if (checksumWord == remainingWords.minus(newWord).first()) {
                println("Flag: $flag")
                println("Words: $flagWords")
                println("Remaining words: $remainingWords")
            }
        }
        return FlagContext(flag, remainingWords.minus(newWord))
    }
    return null
}

private fun getChecksumWord(flag: String, remainingBitsCount: Int): String {
    val remainingBits = flag.toByteArray()
        .joinToString("") { it.toBinary() }
        .takeLast(remainingBitsCount)
    val checksum = Hashing.sha256().hashBytes(flag.toByteArray()).asBytes()[0].toBinary()
    return wordlist[Integer.valueOf(remainingBits + checksum, 2)]
}

class FlagContext(val flag: String, val words: List<String>)