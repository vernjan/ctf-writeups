package cz.vernjan.he19

fun String.hexToAscii(): String {
    val output = StringBuilder()

    for (i in 0..(length - 2) step 2) {
        val str = substring(i, i + 2)
        output.append(Integer.parseInt(str, 16).toChar())
    }

    return output.toString()
}

fun String.asciiToHex(): String = toCharArray().joinToString { Integer.toHexString(it.toInt()) }
