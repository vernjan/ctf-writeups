package cz.vernjan.he19.ch17

import java.nio.file.Files
import java.nio.file.Paths

const val WIDTH = 10
const val CHANNELS = 4 // RGBA


fun main() {
    for (i in (0..4)) {
        val path = Paths.get("d:\\Shared\\17\\_out$i.png.extracted\\29")
//        val path = Paths.get("d:\\Shared\\17\\simples\\_simple0$i.png.extracted\\29")
        println("Filtering $i")

//        for (j in (0 until CHANNELS)) {

            val bytes = Files.readAllBytes(path).asSequence()
//                .take(1000)
                .filterIndexed { index, _ -> filter( {index2 -> index2 % (WIDTH * CHANNELS) != index / (WIDTH * CHANNELS)}, index, "row") }
                .filterIndexed { index, _ -> filter( {index2 -> index2 % CHANNELS != 3}, index, "channel") }
                .toList()
                .toByteArray()

//            Files.write(Paths.get("d:\\Shared\\17\\_out$i.png.extracted\\29-filtered"), bytes)
//            Files.write(Paths.get("d:\\Shared\\17\\_out$i.png.extracted\\29-$j.txt"), bytes)
            Files.write(Paths.get("d:\\Shared\\17\\_out$i.png.extracted\\29-rgb.txt"), bytes)
//        }
    }
}

fun filter(predicate: (index: Int) -> Boolean, index: Int, name: String): Boolean {
    return if (predicate(index)) {
//        println("Accepting $name/$index")
        true
    } else {
//        println("Refusing $name/$index")
        false
    }
}