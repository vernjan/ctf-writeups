package cz.vernjan.ctf.hv20

import cz.vernjan.ctf.Resources
import cz.vernjan.ctf.hexToByteArray
import cz.vernjan.ctf.toHex
import java.lang.StringBuilder
import java.math.BigInteger
import kotlin.experimental.xor
import kotlin.system.exitProcess

private val keystreamConst = "deadbeefc0123456789a".hexToByteArray()
private val mulConst = BigInteger("cccccccccccccccd", 16)
private val ffffffffffffff00 = BigInteger("ffffffffffffff00", 16)

// Santa's encrypted data
private val encrypted = "0a114843de120e14cea06ea749cd8e8035080d53c16d1a6884eb28a0278a8fa4".hexToByteArray()

fun main() {
    val hashesStream = Resources.asStream("hv20/hashes.bin")

    var counter = 0
    var hash: ByteArray

    while (hashesStream.available() > 0) {
        counter++

        hash = hashesStream.readNBytes(16)

        if (counter % 100000 == 0) {
            println("Progress ... $counter")
        }

        val sb = StringBuilder()
        for (i in encrypted.indices) {
            val encByte = encrypted[i]
            val keyByte = getKeystreamChar(i, hash)
            sb.append(encByte.xor(keyByte).toChar())
        }
        if (sb.contains("HV20")) {
            println("Counter: $counter, hash: ${hash.toHex()}")
            println(sb.toString())
            exitProcess(0)
        }
    }
}

private fun getKeystreamChar(i: Int, hash: ByteArray): Byte {
    val hashByte = hash[i % 16]
    val hashByteXorCounter = hash[i % 16].xor(i.toByte())

    val hashByteLong = BigInteger.valueOf(hashByte.toUByte().toLong()).add(ffffffffffffff00)
    val mulResult = mulConst.multiply(hashByteLong).shiftRight(64)
    val mulResultShr3 = mulResult.shr(3)
    val mulResultShr3Shl2 = mulResultShr3.shl(2)
    val mulResultAdd = mulResultShr3.add(mulResultShr3Shl2)
    val mulResultAddSelf = mulResultAdd.add(mulResultAdd)
    val mulResultSub = hashByteLong.subtract(mulResultAddSelf)

    val keystreamConstIndex = mulResultSub.toInt()
    val keystreamConstByte = keystreamConst[keystreamConstIndex]

    return hashByteXorCounter.xor(keystreamConstByte)
}