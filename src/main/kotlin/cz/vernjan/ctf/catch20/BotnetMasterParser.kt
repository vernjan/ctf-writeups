package cz.vernjan.ctf.catch20

import cz.vernjan.ctf.Resources
import cz.vernjan.ctf.decodeBase64
import cz.vernjan.ctf.hexToAscii
import cz.vernjan.ctf.hexToByteArray
import org.json.simple.JSONArray
import org.json.simple.JSONObject
import org.json.simple.parser.JSONParser

fun main() {
    val packets: JSONArray = JSONParser().parse(Resources.asReader("catch20/packets.json")) as JSONArray

    packets.forEach { packet ->
        val layers = ((packet as JSONObject)["_source"] as JSONObject)["layers"] as JSONObject
        val ip = layers["ip"] as JSONObject
        val ipSrc = ip["ip.src"] as String
        val ipDst = ip["ip.dst"] as String
        val tcp = layers["tcp"] as JSONObject
        val tcpDstPort = tcp["tcp.dstport"] as String
        val data: String = ((layers["data"] as JSONObject)["data.data"] as String)
            .replace(":", "")
        val message = decode(data.hexToByteArray())
        val important = if (message.contains("(;;ready;;Linux|wait;;\\d+$)".toRegex())) " " else "!"

        println("%-12s --> %-12s/%s: %s %s".format(ipSrc, ipDst, tcpDstPort, important, message))
    }
}

