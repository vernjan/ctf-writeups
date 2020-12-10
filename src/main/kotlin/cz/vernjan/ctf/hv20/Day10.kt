package cz.vernjan.ctf.hv20

import cz.vernjan.ctf.Resources
import org.jgrapht.alg.clique.BronKerboschCliqueFinder
import org.jgrapht.alg.clique.DegeneracyBronKerboschCliqueFinder
import org.jgrapht.alg.clique.PivotBronKerboschCliqueFinder
import org.jgrapht.graph.DefaultEdge
import org.jgrapht.graph.SimpleGraph
import org.jgrapht.nio.dimacs.DIMACSImporter
import org.jgrapht.util.SupplierUtil
import java.util.function.Supplier

private val kids =
    "104 118 55 51 123 110 111 116 95 84 72 69 126 70 76 65 71 33 61 40 124 115 48 60 62 83 79 42 82 121 125 45 98 114 101 97 100".split(
        " "
    )

// !!!!!
// Does not work !!! Only a subset of cliques is found..
// !!!!!

fun main() {
    printCliques()

    val cliques: List<List<String>> = Resources.asLines("hv20/cliques.txt").map { it.split(",") }

    kids.forEach { kid ->
        println("Kid: $kid")
        println(cliques.filter { clique -> clique.contains(kid) }.maxBy { it.size }?.size)
    }
}

private fun printCliques() {
    val g = SimpleGraph<String, DefaultEdge>(DefaultEdge::class.java)
    Resources.asLines("hv20/edges.txt").map {
        val v1 = it.split(" ")[0]
        val v2 = it.split(" ")[1]
        g.addVertex(v1)
        g.addVertex(v2)
        g.addEdge(v1, v2)
    }

    val alg = BronKerboschCliqueFinder(g)
    for (x in alg.iterator()) {
        println(x)
    }
}
