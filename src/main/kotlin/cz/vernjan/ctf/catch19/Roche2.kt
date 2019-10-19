package cz.vernjan.ctf.catch19

import cz.vernjan.ctf.catch19.Mode.*
import cz.vernjan.ctf.hexToAscii
import java.lang.StringBuilder
import kotlin.system.exitProcess


private val ciphertext =
    "463216327617246f67406f1266075ec622606c6671765537066636596e621e64e622c2b006066961c66e621f067676e77c6e665167a462c4b50477433617754222d7043542885747df6dd575970417d435223000"

// TODO inverse key?
private val keys = listOf(
    intArrayOf(3, 5, 4, 2, 1, 6),
    intArrayOf(5, 6, 3, 4, 2, 1, 7),
    // WED
    intArrayOf(6, 3, 7, 4, 5, 2, 1, 8),
    // FRI
    intArrayOf(5, 1, 6, 7, 4, 3, 2, 8),
    intArrayOf(4, 5, 3, 2, 1, 6)
)


/**
 * permutation function
 * @param str string to calculate permutation for
 * @param l starting index
 * @param r end index
 */
private fun permute(str: String, l: Int, r: Int) {
    var str = str
    if (l == r) {
        println(str)



        for (mode in listOf(DECRYPT_FROM_COLUMNS, DECRYPT_FROM_LINES)) {
            val keyy = str.map { Integer.parseInt(it.toString()) }.toIntArray()
            val level1 = transpose(ciphertext, keyy, mode)
            check(level1)
        }

    } else {
        for (i in l..r) {
            str = swap(str, l, i)
            permute(str, l + 1, r)
            str = swap(str, l, i)
        }
    }
}

/**
 * Swap Characters at position
 * @param a string value
 * @param i position 1
 * @param j position 2
 * @return swapped string
 */
fun swap(a: String, i: Int, j: Int): String {
    val temp: Char
    val charArray = a.toCharArray()
    temp = charArray[i]
    charArray[i] = charArray[j]
    charArray[j] = temp
    return String(charArray)
}


fun main3() {
//    val str = "012345"
//    val n = str.length
//    permute(str, 0, n - 1)


//    for (i in 10..10000000) {
//        for (mode in listOf(DECRYPT_FROM_COLUMNS, DECRYPT_FROM_LINES)) {
//
//            val toIntArray = i.toString().map { Integer.parseInt(it.toString()) }.toIntArray()
//            println(toIntArray.contentToString())
//            val level1 = transpose(ciphertext, toIntArray, mode)
//            check(level1)
//        }
//    }


}


fun main() {
    for (mode in listOf(DECRYPT_FROM_COLUMNS, DECRYPT_FROM_LINES, ENCRYPT_READ_COLUMNS, ENCRYPT_READ_LINES)) {

        for (key1 in keys) {
            val level1 = transpose(ciphertext, key1, mode)
            check(level1)

            for (key2 in keys) {
                val level2 = transpose(level1, key2, mode)
                check(level2)

                for (key3 in keys) {
                    val level3 = transpose(level2, key3, mode)
                    check(level3)

                    for (key4 in keys) {
                        val level4 = transpose(level3, key4, mode)
                        check(level4)

                        for (key5 in keys) {
                            val level5 = transpose(level4, key5, mode)
                            check(level5)
                        }
                    }
                }
            }
        }
    }
}

fun check(res: String) {
    val ascii = res.hexToAscii()
//    println(ascii)
    if (ascii.contains("FLAG")) {
        println("BING !!!")
        println(ascii)
        exitProcess(0)
    }
}

enum class Mode {
    ENCRYPT_READ_LINES,
    ENCRYPT_READ_COLUMNS,
    DECRYPT_FROM_LINES,
    DECRYPT_FROM_COLUMNS
}

fun transpose(input: String, key: IntArray, mode: Mode): String {
    require(input.length % key.size == 0) { "Invalid key length" }

    val numberOfColumns = key.size
    val numberOfRows = input.length / numberOfColumns

    println("Columns: $numberOfColumns, rows: $numberOfRows ")

    return when (mode) {
        ENCRYPT_READ_LINES,
        DECRYPT_FROM_LINES -> {
            val array = encrypt(numberOfColumns, key, numberOfRows, input)
            readByLines(array)
        }

        ENCRYPT_READ_COLUMNS -> {
            val array = encrypt(numberOfColumns, key, numberOfRows, input)
            readByColumns(array)
        }
        DECRYPT_FROM_COLUMNS -> {
            val array = Array(numberOfRows) { rowIndex ->
                CharArray(numberOfColumns) { columnIndex ->
                    val transposedColumnIndex = key[columnIndex] -1 // TODO 0 based keys
                    input[transposedColumnIndex * numberOfRows + rowIndex]
                }
            }
            readByColumns(array)
        }
    }
}

private fun encrypt(
    numberOfColumns: Int,
    key: IntArray,
    numberOfRows: Int,
    input: String
): Array<CharArray> {
    return Array(numberOfColumns) { columnIndex ->
        val transposedColumnIndex = key[columnIndex] -1// TODO 0 based
        CharArray(numberOfRows) { rowIndex ->
            input[numberOfColumns * rowIndex + transposedColumnIndex]
        }
    }
}

fun readByLines(array: Array<CharArray>): String {
    val result = StringBuilder()
    for (rowIndex in 0 until array.first().size) {
        for (columnIndex in 0 until array.size) {
            result.append(array[columnIndex][rowIndex])
        }
    }
    return result.toString()
}

fun readByColumns(array: Array<CharArray>): String {
    val result = StringBuilder()
    for (columnIndex in 0 until array.size) {
        for (rowIndex in 0 until array.first().size) {
            result.append(array[columnIndex][rowIndex])
        }
    }
    return result.toString()
}