package cz.vernjan.ctf.hv19.day08

val CCs = listOf(
    """QVXSZUVY\ZYYZ[a""",
    """QOUW[VT^VY]bZ_""",
    """SPPVSSYVV\YY_\\]""",
    """RPQRSTUVWXYZ[\]^""",
    """QTVWRSVUXW[_Z`\b"""
)

const val FLAG = "SlQRUPXWVo\\Vuv_n_\\ajjce"

fun main() {
    println("Credit card numbers:")
    for (cc in CCs) {
        decrypt(cc)
        println()
    }

    println("Flag:")
    decrypt(FLAG)
}

private fun decrypt(cipherText: String) {
    for ((i, ch) in cipherText.withIndex()) {
        print((ch.toInt() - 30 - i).toChar())
    }
}