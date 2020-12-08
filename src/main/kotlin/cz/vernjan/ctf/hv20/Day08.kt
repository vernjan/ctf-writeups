package cz.vernjan.ctf.hv20

fun main() {
    val searchList = "QcXgWw9d4"
    val replacementList = "ljhc0hsA5"

    "####H#V#2#0#{#h#t#t#p#s#:#/#/#w#w#w#.#y#o#u#t#u#b#e#.#c#o#m#/#w#a#t#c#h#?#v#=#d#Q#w#4#w#9#W#g#X#c#Q#}####"
        .forEachIndexed { i, c ->
            if (c != '#') {
                if (i > 77 && i < 98 && i != 82) {
                    val index = searchList.indexOf(c)
                    print(replacementList[index])
                } else if (i == 98) {
                    print("0")
                } else {
                    print(c)
                }
            }
        }
}