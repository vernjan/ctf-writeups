package cz.vernjan.ctf.he14.ch15

import cz.vernjan.ctf.QRCode
import cz.vernjan.ctf.Resources

fun main() {
    val a: List<Boolean> = Resources.asLines("he14/ch15/a.txt").toBooleans()
    val b: List<Boolean> = Resources.asLines("he14/ch15/b.txt").toBooleans()
    val c: List<Boolean> = Resources.asLines("he14/ch15/c.txt").toBooleans()
    val d: List<Boolean> = Resources.asLines("he14/ch15/d.txt").toBooleans()

    val result = arrayOfNulls<Boolean>(a.size)

    for (i in 0 until a.size) {
        result[i] = ((!a[i] && b[i]) || c[i]) xor d[i]
    }

    val qrData: Array<BooleanArray> = result
        .requireNoNulls()
        .toList()
        .chunked(25) { it.toBooleanArray() }
        .toTypedArray()

    QRCode(qrData).render()
}

private fun List<String>.toBooleans(): List<Boolean> = flatMap { line -> line.map { it == '1' } }
