package cz.vernjan.ctf.catch19

import cz.vernjan.ctf.decodeBase64
import java.nio.file.Files
import java.nio.file.Path

fun main() {
    val client = BerserkerClient("781473d072a8de7d454cddd463414034")
    val assignment = client.fetchAssignment()

    val (code, initNumber) = assignment
        .lines()[0]
        .substring(17)
        .split(";")
        .map { it.decodeBase64() }

    println("Unique initiation number: $initNumber")

    val codeFixed = fixLineIndents(code
        .replace("^[import]{6} ".toRegex(), "import ")
        .replace("^[def]{3} ".toRegex(), "def ")
        .replace("^[main]{4}".toRegex(), "main")
        .replace("[return]{6} ".toRegex(), "return ")
        .replace("else$".toRegex(), "else:")
        .replace("if .*[^:]$".toRegex()) { "${it.value}:" }
        .replace("+ =", "+="))

    // save fixed code to file
    val scriptPath: Path = createTempFile("infiltration", ".py").toPath()
    Files.writeString(scriptPath, codeFixed)

    // execute script
    val processBuilder = ProcessBuilder("python", scriptPath.toString(), "--number", initNumber)
    processBuilder.redirectErrorStream(true)
    val process = processBuilder.start()
    val exitStatus = process.waitFor()
    println("Process exited with: $exitStatus")

    val processOutput = String(process.inputStream.readAllBytes())
    println(processOutput)

    val answer = processOutput.lines()[0].substring(13)
    println("B-code: '$answer'")

    client.sendAnswer(answer)
}

private fun fixLineIndents(code: String): String {

    fun getLineIndent(line: String) = line.length - line.trimStart().length

    val sb = StringBuilder()
    var expectedIndent: Int? = null

    for (line in code.lines()) {
        if (expectedIndent != null) {
            val currentIndent = getLineIndent(line)
            if (currentIndent != expectedIndent) {
                sb.append("\t")
            }
            expectedIndent = null
        }

        sb.append(line)

        if (line.matches("\\s*(def|if|else|for).*".toRegex())) {
            val lineFixed = sb.lines().last() // cant just use `line`, it could have been fixed ..
            expectedIndent = (getLineIndent(lineFixed)) + 1
        }

        sb.append("\n")
    }

    return sb.toString()
}

private fun String.toRegex() = toRegex(RegexOption.MULTILINE)