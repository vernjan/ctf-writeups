package cz.vernjan.ctf.catch19

private val ITEMS = mapOf(
    "artificial intelligence" to 1,
    "automatic transmission" to 1,
    "yumy food" to 0,
    "cute kitty" to 0,
    "electric engine" to 1,
    "large hard drive" to 1,
    "lovely puppy" to 0,
    "hope" to 0,
    "love" to 0,
    "fear" to 0,
    "fast CPU" to 1,
    "pretty children" to 0,
    "sweet baby" to 0,
    "drone swarm" to 1,
    "mineral oil" to 1,
    "resistor 10 Ohm" to 1
)

fun main() {
    val client = BerserkerClient("c2619b989b7ae5eaf6df8047e6893405")
    val assignment = client.fetchAssignment()

    val answer = assignment
        .substringAfter('[')
        .substringBefore(']')
        .split(", ")
        .map { ITEMS[it] }
        .joinToString(separator = "")

    client.sendAnswer(answer)
}