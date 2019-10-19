package cz.vernjan.ctf.catch19

import cz.vernjan.ctf.catch19.GridType.COLUMNS
import cz.vernjan.ctf.catch19.GridType.ROWS


private val ciphertext =
    "463216327617246f67406f1266075ec622606c6671765537066636596e621e64e622c2b006066961c66e621f067676e77c6e665167a462c4b50477433617754222d7043542885747df6dd575970417d435223000"

enum class GridType {
    ROWS, COLUMNS
}

@Suppress("ArrayInDataClass")
data class Grid(val data: Array<CharArray>, val gridType: GridType) {

    fun readByRows(): String {
        return when (gridType) {
            ROWS -> print()
            COLUMNS -> printInverted()
        }
    }

    fun readByColumns(): String {
        return when (gridType) {
            ROWS -> printInverted()
            COLUMNS -> print()
        }
    }

    private fun print(): String {
        val result = StringBuilder()
        for (i in 0 until data.size) {
            for (j in 0 until data.first().size) {
                result.append(data[i][j])
            }
        }
        return result.toString()
    }

    private fun printInverted(): String {
        val result = StringBuilder()
        for (i in 0 until data.first().size) {
            for (j in 0 until data.size) {
                result.append(data[j][i])
            }
        }
        return result.toString()
    }
}


fun transposeColumns(input: String, key: IntArray): Grid {
    require(input.length % key.size == 0) { "Invalid key length" }

    val numberOfColumns = key.size
    val numberOfRows = input.length / numberOfColumns

    println("Rows: $numberOfRows, Columns: $numberOfColumns")

    // read into array of columns
    val columns = Array(numberOfColumns) { columnIndex ->
        CharArray(numberOfRows) { rowIndex ->
            input[numberOfColumns * rowIndex + columnIndex]
        }
    }

    println()
    columns.forEach { println(it.contentToString()) }

    // swap columns
    val invertKey = invertKey(key)
    val columnsShuffled = Array(numberOfColumns) { columnIndex ->
        columns[invertKey[columnIndex] - 1]
    }

    println()
    columnsShuffled.forEach { println(it.contentToString()) }

    return Grid(columnsShuffled, COLUMNS)
}

fun transposeRows(input: String, key: IntArray): Grid {
    require(input.length % key.size == 0) { "Invalid key length" }

    val numberOfRows = key.size
    val numberOfColumns = input.length / numberOfRows

    println("Rows: $numberOfRows, Columns: $numberOfColumns")

    // read into array of rows
    val rows = Array(numberOfRows) { rowIndex ->
        CharArray(numberOfColumns) { columnIndex ->
            input[numberOfColumns * rowIndex + columnIndex]
        }
    }

    println()
    rows.forEach { println(it.contentToString()) }

    // swap rows
    val invertKey = invertKey(key)
    val rowsShuffled = Array(numberOfRows) { rowIndex ->
        rows[invertKey[rowIndex] - 1]
    }

    println()
    rowsShuffled.forEach { println(it.contentToString()) }

    return Grid(rowsShuffled, ROWS)
}

fun invertKey(key: IntArray): IntArray {
    val inverse = IntArray(key.size)
    for (i in 0 until key.size) {
        inverse[key[i] - 1] = i + 1
    }
    return inverse
}

fun key(vararg elements: Int) = intArrayOf(*elements)
