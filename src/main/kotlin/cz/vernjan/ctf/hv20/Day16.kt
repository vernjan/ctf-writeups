package cz.vernjan.ctf.hv20

val grid = arrayOf(
    charArrayOf('#', '#', '#', '6', '_', 'e', '#', '#', '#', '#', '#', '#'),
    charArrayOf('#', '#', '#', 'i', '{', 'a', '#', '#', '#', '#', '#', '#'),
    charArrayOf('#', '#', '#', 'e', 's', '3', '#', '#', '#', '#', '#', '#'),
    charArrayOf('H', 'V', '7', '_', 'w', 'e', 'o', '@', 's', 'i', 's', 'l'),
    charArrayOf('h', '_', 'e', '0', 'k', '_', '_', 't', '_', 'n', 's', 'o'),
    charArrayOf('o', 'a', '_', 'c', 'd', 'a', '4', 'r', '5', '2', 'c', '_'),
    charArrayOf('#', '#', '#', '_', 'n', 's', '#', '#', '#', '#', '#', '#'),
    charArrayOf('#', '#', '#', '1', '1', 't', '#', '#', '#', '#', '#', '#'),
    charArrayOf('#', '#', '#', '}', 'p', 'h', '#', '#', '#', '#', '#', '#')
)

val gridClone = grid.map { it.clone() }.toTypedArray()

fun LR(col1: Int, col2: Int) = linkedMapOf(
    Pair(0, col1) to Pair(3, col2),
    Pair(3, col2) to Pair(4, col2),
    Pair(4, col2) to Pair(5, col2),
    Pair(5, col2) to Pair(8, col1),
    Pair(8, col1) to Pair(7, col1),
    Pair(7, col1) to Pair(6, col1),
    Pair(6, col1) to Pair(5, col1),
    Pair(5, col1) to Pair(4, col1),
    Pair(4, col1) to Pair(3, col1),
    Pair(3, col1) to Pair(2, col1),
    Pair(2, col1) to Pair(1, col1)
)

fun UD(row: Int) = linkedMapOf(
    Pair(row, 11) to Pair(row, 0),
    Pair(row, 0) to Pair(row, 1),
    Pair(row, 1) to Pair(row, 2),
    Pair(row, 2) to Pair(row, 3),
    Pair(row, 3) to Pair(row, 4),
    Pair(row, 4) to Pair(row, 5),
    Pair(row, 5) to Pair(row, 6),
    Pair(row, 6) to Pair(row, 7),
    Pair(row, 7) to Pair(row, 8),
    Pair(row, 8) to Pair(row, 9),
    Pair(row, 9) to Pair(row, 10)
)

fun F() = linkedMapOf(
    Pair(2, 3) to Pair(3, 2),
    Pair(3, 2) to Pair(4, 2),
    Pair(4, 2) to Pair(5, 2),
    Pair(5, 2) to Pair(6, 3),
    Pair(6, 3) to Pair(6, 4),
    Pair(6, 4) to Pair(6, 5),
    Pair(6, 5) to Pair(5, 6),
    Pair(5, 6) to Pair(4, 6),
    Pair(4, 6) to Pair(3, 6),
    Pair(3, 6) to Pair(2, 5),
    Pair(2, 5) to Pair(2, 4)
)

fun B() = linkedMapOf(
    Pair(0, 3) to Pair(0, 4),
    Pair(0, 4) to Pair(0, 5),
    Pair(0, 5) to Pair(3, 8),
    Pair(3, 8) to Pair(4, 8),
    Pair(4, 8) to Pair(5, 8),
    Pair(5, 8) to Pair(8, 5),
    Pair(8, 5) to Pair(8, 4),
    Pair(8, 4) to Pair(8, 3),
    Pair(8, 3) to Pair(5, 0),
    Pair(5, 0) to Pair(4, 0),
    Pair(4, 0) to Pair(3, 0)
)

fun main() {
    printAsGrid()
    doSomeTests()

}

/**
 * Operations:
 */

fun left() {
    rotFaceRight(3, 0)
    rotSide(LR(3, 11))
}

fun leftReverse() {
    rotFaceLeft(3, 0)
    rotSide(reverse(LR(3, 11)))
}

fun right() {
    rotFaceRight(3, 6)
    rotSide(reverse(LR(5, 9)))
}

fun rightReverse() {
    rotFaceLeft(3, 6)
    rotSide(LR(5, 9))
}

fun up() {
    rotFaceRight(0, 3)
    rotSide(UD(3))
}

fun upReverse() {
    rotFaceLeft(0, 3)
    rotSide(reverse(UD(3)))
}

fun down() {
    rotFaceRight(6, 3)
    rotSide(reverse(UD(5)))
}

fun downReverse() {
    rotFaceLeft(6, 3)
    rotSide(UD(5))
}

fun front() {
    rotFaceRight(3, 3)
    rotSide(F())
}

fun frontReverse() {
    rotFaceLeft(3, 3)
    rotSide(reverse(F()))
}

fun back() {
    rotFaceRight(3, 9)
    rotSide(B())
}

fun backReverse() {
    rotFaceLeft(3, 9)
    rotSide(reverse(B()))
}

/**
 * Helper methods:
 */

private fun reverse(shifts: Map<Pair<Int, Int>, Pair<Int, Int>>) =
    shifts.entries.reversed().map { entry -> entry.value to entry.key }.toMap()

private fun rotSide(shifts: Map<Pair<Int, Int>, Pair<Int, Int>>) {
    repeat(3) {
        val temp = grid[shifts.keys.first().first][shifts.keys.first().second]
        shifts.forEach { (to, from) ->
            grid[to.first][to.second] = grid[from.first][from.second]
        }
        grid[shifts.values.last().first][shifts.values.last().second] = temp
    }
}

private fun rotFaceLeft(upperIndex: Int, leftIndex: Int) {
    var temp = grid[upperIndex][leftIndex]
    grid[upperIndex][leftIndex] = grid[upperIndex][leftIndex + 2]
    grid[upperIndex][leftIndex + 2] = grid[upperIndex + 2][leftIndex + 2]
    grid[upperIndex + 2][leftIndex + 2] = grid[upperIndex + 2][leftIndex]
    grid[upperIndex + 2][leftIndex] = temp

    temp = grid[upperIndex][leftIndex + 1]
    grid[upperIndex][leftIndex + 1] = grid[upperIndex + 1][leftIndex + 2]
    grid[upperIndex + 1][leftIndex + 2] = grid[upperIndex + 2][leftIndex + 1]
    grid[upperIndex + 2][leftIndex + 1] = grid[upperIndex + 1][leftIndex]
    grid[upperIndex + 1][leftIndex] = temp
}

private fun rotFaceRight(upperIndex: Int, leftIndex: Int) {
    var temp = grid[upperIndex][leftIndex]
    grid[upperIndex][leftIndex] = grid[upperIndex + 2][leftIndex]
    grid[upperIndex + 2][leftIndex] = grid[upperIndex + 2][leftIndex + 2]
    grid[upperIndex + 2][leftIndex + 2] = grid[upperIndex][leftIndex + 2]
    grid[upperIndex][leftIndex + 2] = temp

    temp = grid[upperIndex][leftIndex + 1]
    grid[upperIndex][leftIndex + 1] = grid[upperIndex + 1][leftIndex]
    grid[upperIndex + 1][leftIndex] = grid[upperIndex + 2][leftIndex + 1]
    grid[upperIndex + 2][leftIndex + 1] = grid[upperIndex + 1][leftIndex + 2]
    grid[upperIndex + 1][leftIndex + 2] = temp
}

fun printAsString() {
    println(grid.joinToString("") { it.filter { it != '#' }.joinToString("") })
}

fun printAsGrid() {
    println(grid.joinToString("\n") { it.toList().chunked(3).joinToString(" ") })
    println("")
}

/**
 * Tests:
 */

private fun doSomeTests() {
    right()
    rightReverse()
    verifyItIsTheSame()

    left()
    leftReverse()
    verifyItIsTheSame()

    up()
    upReverse()
    verifyItIsTheSame()

    down()
    downReverse()
    verifyItIsTheSame()

    front()
    frontReverse()
    verifyItIsTheSame()

    back()
    backReverse()
    verifyItIsTheSame()

    right()
    right()
    right()
    right()
    verifyItIsTheSame()
}

private fun verifyItIsTheSame() {
    grid.forEachIndexed { i, arr ->
        if (!gridClone[i].contentEquals(arr)) {
            throw AssertionError("FUCK at $i!")
        }
    }
}
