package cz.vernjan.ctf.hv19.day09

import cz.vernjan.ctf.QRCode
import cz.vernjan.ctf.Resources
import java.awt.image.BufferedImage

fun main() {
    val codeImage: BufferedImage = Resources.asImage("hv19/day09/barcode.png")
    val qrCode = QRCode.fromImage(codeImage, 5)
    val rule30: List<List<Boolean>> = generateRule30(33)

    qrCode.data.forEachIndexed { rowIndex, row ->
        val ruleSize = rule30[rowIndex].size
        println("ruleSize $ruleSize")
        val startIndex = ((qrCode.width - ruleSize) / 2) + 1 // Rule 30 was applied on center + 1
        val stopIndex = startIndex + ruleSize
        println("startIndex $startIndex, stopIndex $stopIndex")

        row.forEachIndexed { colIndex, _ ->
            if (colIndex in startIndex until stopIndex) {
                qrCode.data[rowIndex][colIndex] = qrCode.data[rowIndex][colIndex] xor rule30[rowIndex][colIndex - startIndex]
            }
        }
    }

    qrCode.printASCII()
    qrCode.render()
}

fun generateRule30(steps: Int): List<List<Boolean>> {
    val data: MutableList<List<Boolean>> = mutableListOf()
    var generation: List<Boolean> = listOf(true)
    data.add(generation)

    var i = 1
    while (i++ < steps) {
        generation = nextGeneration(generation)
        println(generation)
        data.add(generation)
    }

    return data
}

fun nextGeneration(currentGeneration: List<Boolean>): List<Boolean> {
    val nextStep = currentGeneration.toMutableList()
    nextStep.add(0, false)
    nextStep.add(false)

    return nextStep.mapIndexed { index, _ ->
        nextCell(nextStep, index)
    }.toList()
}

fun nextCell(generation: List<Boolean>, index: Int): Boolean {
    val left = generation.getOrNull(index - 1) ?: false
    val middle = generation[index]
    val right = generation.getOrNull(index + 1) ?: false

    return when {
        left && middle && right -> false
        left && middle && !right -> false
        left && !middle && right -> false
        left && !middle && !right -> true
        !left && middle && right -> true
        !left && middle && !right -> true
        !left && !middle && right -> true
        !left && !middle && !right -> false
        else -> throw RuntimeException("Impossible")
    }
}

