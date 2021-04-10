@file:Suppress("UnstableApiUsage")

package cz.vernjan.ctf.he21

import com.google.common.hash.Hashing
import cz.vernjan.ctf.toHex

fun main() {
    val adjectives = listOf("Yummy", "Sweet", "Cherry", "Groovy", "Chocolate")
    val candies = listOf("Cake", "Doughnut", "Pie", "Lollipop", "Gum")

    for (adjective in adjectives) {
        for (candy in candies) {
            println("Testing $adjective $candy ..")
            for (i in 0..10_000_000) {
                val number = i.toString().padStart(8, '0')
                val product = "$number $adjective $candy"
                val hash = Hashing.sha256().hashBytes(product.toByteArray()).asBytes().toHex()
                if (hash.contains("c01a") && hash.contains("decaf")) {
                    println(">>> $product ($hash)")
                }
            }
        }
    }
}