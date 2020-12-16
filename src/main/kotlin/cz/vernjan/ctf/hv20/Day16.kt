package cz.vernjan.ctf.hv20

import java.lang.StringBuilder

var grid = arrayOf(
    charArrayOf('#', '#', '#', '6', '_', 'e', '#', '#', '#', '#', '#', '#'),
    charArrayOf('#', '#', '#', 'i', '{', 'a', '#', '#', '#', '#', '#', '#'),
    charArrayOf('#', '#', '#', 'e', 's', '3', '#', '#', '#', '#', '#', '#'),
    charArrayOf('H', 'V', '7', '_', 'w', 'e', 'o', '@', 's', 'i', 's', 'l'),
    charArrayOf('h', '_', 'e', '0', 'k', '_', '_', 't', '_', 'n', 's', 'o'),
    charArrayOf('o', 'a', '_', 'c', 'd', 'a', '4', 'r', '5', '2', 'c', '_'),
    charArrayOf('#', '#', '#', '_', 'n', 's', '#', '#', '#', '#', '#', '#'),
    charArrayOf('#', '#', '#', 'l', 'l', 't', '#', '#', '#', '#', '#', '#'),
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
//    printGrid()
//    MoveCube.R.move()
//    printGrid()

    // System.exit(0)

//    for (moveCube in MoveCube.values()) {
//        grid = gridClone.map { it.clone() }.toTypedArray()
//        println("Move cube: $moveCube")

    for (move1 in Move.values()) {
        println("Move: $move1")
        for (move2 in Move.values()) {
            for (move3 in Move.values()) {
                for (move4 in Move.values()) {
                    for (move5 in Move.values()) {
                        grid = gridClone.map { it.clone() }.toTypedArray()
                        move1.move()
                        move2.move()
                        move3.move()
                        move4.move()
                        move5.move()
                        val result = gridToString()
                        if (result.contains("HV20{")) {
                            println(result)
                            //printGrid()
                        }
//                        for (move6 in Move.values()) {
//                            move6.move()
//                            val result = gridToString()
//                            if (result.contains("HV20{")) {
//                                println(result)
//                            }
//                        }

                    }
//                    }
                }

            }
        }
    }
}

/**
 * Operations:
 */

enum class Move {

    LEFT {
        override fun move() {
            rotFaceRight(3, 0)
            rotSide(LR(3, 11))
        }
    },
    LEFT2 {
        override fun move() {
            LEFT.move()
            LEFT.move()
        }
    },
    LEFT_R {
        override fun move() {
            rotFaceLeft(3, 0)
            rotSide(reverse(LR(3, 11)))
        }
    },
    RIGHT {
        override fun move() {
            rotFaceRight(3, 6)
            rotSide(reverse(LR(5, 9)))
        }
    },
    RIGHT2 {
        override fun move() {
            RIGHT.move()
            RIGHT.move()
        }
    },
    RIGHT_R {
        override fun move() {
            rotFaceLeft(3, 6)
            rotSide(LR(5, 9))
        }
    },
    UP {
        override fun move() {
            rotFaceRight(0, 3)
            rotSide(UD(3))
        }
    },
    UP2 {
        override fun move() {
            UP.move()
            UP.move()
        }
    },
    UP_R {
        override fun move() {
            rotFaceLeft(0, 3)
            rotSide(reverse(UD(3)))
        }
    },
    DOWN {
        override fun move() {
            rotFaceRight(6, 3)
            rotSide(reverse(UD(5)))
        }
    },
    DOWN2 {
        override fun move() {
            DOWN.move()
            DOWN.move()
        }
    },
    DOWN_R {
        override fun move() {
            rotFaceLeft(6, 3)
            rotSide(UD(5))
        }
    },
    FRONT {
        override fun move() {
            rotFaceRight(3, 3)
            rotSide(F())
        }
    },
    FRONT2 {
        override fun move() {
            FRONT.move()
            FRONT.move()
        }
    },
    FRONT_R {
        override fun move() {
            rotFaceLeft(3, 3)
            rotSide(reverse(F()))
        }
    },
    BACK {
        override fun move() {
            rotFaceRight(3, 9)
            rotSide(B())
        }
    },
    BACK2 {
        override fun move() {
            BACK.move()
            BACK.move()
        }
    },
    BACK_R {
        override fun move() {
            rotFaceLeft(3, 9)
            rotSide(reverse(B()))
        }
    };

    abstract fun move()
}

enum class MoveSpecial {

    MIDDLE_LR_BOTTOM {
        override fun move() {
            rotSide(LR(4, 10))
        }
    },

    MIDDLE_UD_LEFT {
        override fun move() {
            rotSide(UD(4))
        }
    };

    // TODO MIDDLE_FB_RIGHT

    abstract fun move()

}

enum class MoveCube {
    F {
        override fun move() {
            // no-op
        }
    },
    R {
        override fun move() {
            Move.UP.move()
            MoveSpecial.MIDDLE_UD_LEFT.move()
            Move.DOWN_R.move()
        }
    },
    B {
        override fun move() {
            R.move()
            R.move()
        }
    },
    L {
        override fun move() {
            R.move()
            R.move()
            R.move()
        }
    };
//    T, P;

    abstract fun move()
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

fun gridToString(): String {
    val sb = StringBuilder()
    sb.append(faceToString(3, 3))
    sb.append(faceToString(3, 6))
    sb.append(faceToString(3, 9))
    sb.append(faceToString(3, 0))
    sb.append(faceToString(0, 3))
    sb.append(faceToString(6, 3))
    return sb.toString()
}

fun faceToString(upperIndex: Int, leftIndex: Int): String {
    val sb = StringBuilder()
    for (i in 0..2) {
        for (j in 0..2) {
            sb.append(grid[upperIndex + i][leftIndex + j])
        }
    }
    return sb.toString()
}

fun printGrid() {
    println(grid.joinToString("\n") { it.toList().chunked(3).joinToString(" ") })
    println("")
}

/**
 * Tests:
 */

private fun doSomeTests() {
    Move.RIGHT.move()
    Move.RIGHT_R.move()
    verifyItIsTheSame()

    Move.LEFT.move()
    Move.LEFT_R.move()
    verifyItIsTheSame()
}

private fun verifyItIsTheSame() {
    grid.forEachIndexed { i, arr ->
        if (!gridClone[i].contentEquals(arr)) {
            throw AssertionError("FUCK at $i!")
        }
    }
}
