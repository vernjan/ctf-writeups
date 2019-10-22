package cz.vernjan.ctf

import cz.vernjan.ctf.TranspositionType.COLUMNS
import cz.vernjan.ctf.TranspositionType.ROWS

private val printDetails = false

enum class TranspositionType {
    ROWS, COLUMNS
}

@Suppress("ArrayInDataClass")
data class Grid(val data: Array<CharArray>, val type: TranspositionType) {

    fun readByRows(): String {
        return when (type) {
            ROWS -> print()
            COLUMNS -> printInverted()
        }
    }

    fun readByColumns(): String {
        return when (type) {
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

fun tryAllTranspositions(input: String, key: IntArray): List<String> {
    val result = mutableListOf<String>()
    result.add(transposeColumns(input, key).readByColumns())
    result.add(transposeColumns(input, key).readByRows())
    result.add(transposeRows(input, key).readByColumns())
    result.add(transposeRows(input, key).readByRows())
    return result
}

// Convenient method for deciphering all combinations
fun transpose(
    input: String,
    key: IntArray,
    transposeType: TranspositionType,
    readType: TranspositionType,
    padding: Boolean = false
): String  {
    println("Transposing by $transposeType, readType: $readType")
    val result = when (transposeType) {
        ROWS -> when (readType) {
            ROWS -> transposeRows(input, key, padding).readByRows()
            COLUMNS -> transposeRows(input, key, padding).readByColumns()
        }
        COLUMNS -> when (readType) {
            ROWS -> transposeColumns(input, key, padding).readByRows()
            COLUMNS -> transposeColumns(input, key, padding).readByColumns()
        }
    }
    println(result)
    return result
}

fun transposeColumns(input: String, key: IntArray, padding: Boolean = false): Grid {
    val inputPadded = handlePadding(input, key, padding)

    val numberOfColumns = key.size
    val numberOfRows = inputPadded.length / numberOfColumns

    // read into array of columns
    val columns = Array(numberOfColumns) { columnIndex ->
        CharArray(numberOfRows) { rowIndex ->
            inputPadded[numberOfColumns * rowIndex + columnIndex]
        }
    }

    if (printDetails) {
        println()
        print2DimArray(columns)
    }

    // swap columns
    val invertKey = invertKey(key)
    val columnsShuffled = Array(numberOfColumns) { columnIndex ->
        columns[invertKey[columnIndex] - 1]
    }

    if (printDetails) {
        println()
        print2DimArray(columnsShuffled)
    }
    return Grid(columnsShuffled, COLUMNS)
}

private fun handlePadding(input: String, key: IntArray, padding: Boolean): String {
    var inputWithPadding = input
    if (padding) {
        while (inputWithPadding.length % key.size != 0) {
            inputWithPadding += "*"
        }
    } else {
        require(input.length % key.size == 0) { "Invalid key length" }
    }
    return inputWithPadding
}

fun transposeRows(input: String, key: IntArray, padding: Boolean = false): Grid {
    val inputPadded = handlePadding(input, key, padding)

    val numberOfRows = key.size
    val numberOfColumns = inputPadded.length / numberOfRows

    // read into array of rows
    val rows = Array(numberOfRows) { rowIndex ->
        CharArray(numberOfColumns) { columnIndex ->
            inputPadded[numberOfColumns * rowIndex + columnIndex]
        }
    }

    if (printDetails) {
        println()
        print2DimArray(rows)
    }

    // swap rows
    val invertKey = invertKey(key)
    val rowsShuffled = Array(numberOfRows) { rowIndex ->
        rows[invertKey[rowIndex] - 1]
    }

    if (printDetails) {
        println()
        print2DimArray(rowsShuffled)
    }

    return Grid(rowsShuffled, ROWS)
}

private fun print2DimArray(columns: Array<CharArray>) {
    columns.forEach { println(it.contentToString()) }
}

fun invertKey(key: IntArray): IntArray {
    val inverse = IntArray(key.size)
    for (i in 0 until key.size) {
        inverse[key[i] - 1] = i + 1
    }
    return inverse
}

fun key(vararg elements: Int) = intArrayOf(*elements)
