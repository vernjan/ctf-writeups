package cz.vernjan.ctf.hv20

import java.lang.StringBuilder

var cube = arrayOf(
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

private fun cloneCube(cube: Array<CharArray>) = cube.map { it.clone() }.toTypedArray()

val cubeOrig = cloneCube(cube)

fun leftRight(col1: Int, col2: Int) = linkedMapOf(
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

fun upperDown(row: Int) = linkedMapOf(
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

fun front() = linkedMapOf(
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

fun back() = linkedMapOf(
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
    for (move1 in Move.values()) {
        println("First move: $move1")
        for (move2 in Move.values()) {
            for (move3 in Move.values()) {
                for (move4 in Move.values()) {
                    for (move5 in Move.values()) {
                        cube = cloneCube(cubeOrig)
                        move1.doIt()
                        move2.doIt()
                        move3.doIt()
                        move4.doIt()
                        move5.doIt()
                        val result = readCube()
                        if (result.matches("^HV20\\{.*}$".toRegex())) {
                            println(result)
                            println("$move1 -> $move2 -> $move3 -> $move4 -> $move5")
                            printCubeIn2D()
                        }
                    }
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
        override fun doIt() {
            rotFaceRight(3, 0)
            rotSide(leftRight(3, 11))
        }
    },
    LEFT2 {
        override fun doIt() {
            LEFT.doIt()
            LEFT.doIt()
        }
    },
    LEFT_R {
        override fun doIt() {
            rotFaceLeft(3, 0)
            rotSide(reverse(leftRight(3, 11)))
        }
    },
    RIGHT {
        override fun doIt() {
            rotFaceRight(3, 6)
            rotSide(reverse(leftRight(5, 9)))
        }
    },
    RIGHT2 {
        override fun doIt() {
            RIGHT.doIt()
            RIGHT.doIt()
        }
    },
    RIGHT_R {
        override fun doIt() {
            rotFaceLeft(3, 6)
            rotSide(leftRight(5, 9))
        }
    },
    UP {
        override fun doIt() {
            rotFaceRight(0, 3)
            rotSide(upperDown(3))
        }
    },
    UP2 {
        override fun doIt() {
            UP.doIt()
            UP.doIt()
        }
    },
    UP_R {
        override fun doIt() {
            rotFaceLeft(0, 3)
            rotSide(reverse(upperDown(3)))
        }
    },
    DOWN {
        override fun doIt() {
            rotFaceRight(6, 3)
            rotSide(reverse(upperDown(5)))
        }
    },
    DOWN2 {
        override fun doIt() {
            DOWN.doIt()
            DOWN.doIt()
        }
    },
    DOWN_R {
        override fun doIt() {
            rotFaceLeft(6, 3)
            rotSide(upperDown(5))
        }
    },
    FRONT {
        override fun doIt() {
            rotFaceRight(3, 3)
            rotSide(front())
        }
    },
    FRONT2 {
        override fun doIt() {
            FRONT.doIt()
            FRONT.doIt()
        }
    },
    FRONT_R {
        override fun doIt() {
            rotFaceLeft(3, 3)
            rotSide(reverse(front()))
        }
    },
    BACK {
        override fun doIt() {
            rotFaceRight(3, 9)
            rotSide(back())
        }
    },
    BACK2 {
        override fun doIt() {
            BACK.doIt()
            BACK.doIt()
        }
    },
    BACK_R {
        override fun doIt() {
            rotFaceLeft(3, 9)
            rotSide(reverse(back()))
        }
    };

    abstract fun doIt()
}

private fun reverse(steps: Map<Pair<Int, Int>, Pair<Int, Int>>) =
        steps.entries.reversed().map { entry -> entry.value to entry.key }.toMap()

private fun rotSide(steps: Map<Pair<Int, Int>, Pair<Int, Int>>) {
    repeat(3) {
        val temp = cube[steps.keys.first().first][steps.keys.first().second]
        steps.forEach { (to, from) ->
            cube[to.first][to.second] = cube[from.first][from.second]
        }
        cube[steps.values.last().first][steps.values.last().second] = temp
    }
}

private fun rotFaceLeft(upperIndex: Int, leftIndex: Int) {
    var temp = cube[upperIndex][leftIndex]
    cube[upperIndex][leftIndex] = cube[upperIndex][leftIndex + 2]
    cube[upperIndex][leftIndex + 2] = cube[upperIndex + 2][leftIndex + 2]
    cube[upperIndex + 2][leftIndex + 2] = cube[upperIndex + 2][leftIndex]
    cube[upperIndex + 2][leftIndex] = temp

    temp = cube[upperIndex][leftIndex + 1]
    cube[upperIndex][leftIndex + 1] = cube[upperIndex + 1][leftIndex + 2]
    cube[upperIndex + 1][leftIndex + 2] = cube[upperIndex + 2][leftIndex + 1]
    cube[upperIndex + 2][leftIndex + 1] = cube[upperIndex + 1][leftIndex]
    cube[upperIndex + 1][leftIndex] = temp
}

private fun rotFaceRight(upperIndex: Int, leftIndex: Int) {
    var temp = cube[upperIndex][leftIndex]
    cube[upperIndex][leftIndex] = cube[upperIndex + 2][leftIndex]
    cube[upperIndex + 2][leftIndex] = cube[upperIndex + 2][leftIndex + 2]
    cube[upperIndex + 2][leftIndex + 2] = cube[upperIndex][leftIndex + 2]
    cube[upperIndex][leftIndex + 2] = temp

    temp = cube[upperIndex][leftIndex + 1]
    cube[upperIndex][leftIndex + 1] = cube[upperIndex + 1][leftIndex]
    cube[upperIndex + 1][leftIndex] = cube[upperIndex + 2][leftIndex + 1]
    cube[upperIndex + 2][leftIndex + 1] = cube[upperIndex + 1][leftIndex + 2]
    cube[upperIndex + 1][leftIndex + 2] = temp
}

fun readCube(): String {
    val sb = StringBuilder()
    sb.append(readFace(0, 3))
    sb.append(readFace(3, 0))
    sb.append(readFace(3, 3))
    sb.append(readFace(3, 6))
    sb.append(readFace(3, 9))
    sb.append(readFace(6, 3))
    return sb.toString()
}

fun readFace(upperIndex: Int, leftIndex: Int): String {
    val sb = StringBuilder()
    for (i in 0..2) {
        for (j in 0..2) {
            sb.append(cube[upperIndex + i][leftIndex + j])
        }
    }
    return sb.toString()
}

fun printCubeIn2D() {
    println(cube.joinToString("\n") { it.toList().chunked(3).joinToString(" ") })
    println("")
}
