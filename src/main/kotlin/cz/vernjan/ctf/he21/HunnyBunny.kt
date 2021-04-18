package cz.vernjan.ctf.he21

fun main() {
    val encrypted = """
        4ab56415e91e6d5172ee79d9810e30be5da8af18
        c19a3ca5251db76b221048ca0a445fc39ba576a0
        fdb2c9cd51459c2cc38c92af472f3275f8a6b393
        6d586747083fb6b20e099ba962a3f5f457cbaddb
        5587adf42a547b141071cedc7f0347955516ae13
    """.trimIndent()

    encrypted.forEach { ch ->
        val new = when(ch) {
            'a' -> 'd'
            'b' -> 'e'
            'c' -> 'f'
            'd' -> 'a'
            'e' -> 'b'
            'f' -> 'c'
            else -> ch
        }
        print(new)
    }

//    https://hashtoolkit.com/decrypt-hash/?hash=5587dac42d547e141071fbaf7c0347955516db13
    // he2021{
    // hunnybunny
    // ilovemum
    // somuch
    // 	!}

//    he2021{hunnybunnyilovemumsomuch!}

}