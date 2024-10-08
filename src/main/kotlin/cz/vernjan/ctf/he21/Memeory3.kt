package cz.vernjan.ctf.he21

import com.twelvemonkeys.image.ImageUtil
import cz.vernjan.ctf.he19.ch11.MemeoryHttpClient
import java.awt.image.BufferedImage
import java.nio.file.Files
import javax.imageio.ImageIO
import kotlin.math.abs
import kotlin.streams.asSequence

private const val BASE_URL = "http://46.101.107.117:2107"

fun main() {
    MemeoryHttpClient(BASE_URL).use { client ->
        client.obtainSession()

        for (i in 1..10) {
            println("Starting round $i")
            playOneRound(client)
        }
    }
}

class Card(val id: Int, val image: BufferedImage)

private fun playOneRound(client: MemeoryHttpClient) {
    val cardsPath = client.downloadAllCardImages()

    val cards = Files.list(cardsPath).asSequence()
        .sortedBy { cardPath -> Files.size(cardPath) } // Easy optimization
        .map { cardPath ->
            Card(
                cardPath.fileName.toString().removeSuffix(".jpg").toInt(),
                ImageIO.read(cardPath.toFile())
            )
        }
        .toMutableList()

    while (cards.isNotEmpty()) {
        if (cards.size == 2) {
            println("Playing last move")
            client.playOneMove(Pair(cards[0].id, cards[1].id))
            cards.clear()
            break
        }

        val card = cards.removeAt(0)
        println("Searching match for ${card.id}")
        val matchingCard = findMatchingCard(card, cards)

        if (matchingCard != null) {
            client.playOneMove(Pair(card.id, matchingCard.id))
            cards.remove(matchingCard)
        } else {
            println("Damn, no match found for ${card.id}")
            cards.add(card)
        }
    }
}

private fun findMatchingCard(card: Card, cards: MutableList<Card>): Card? {
    for (other in cards) {
        val rots = createRotations(other.image)
        for (rot in rots) {
            if (diffImages(card.image, rot) < 14) {
                println("Pair found: ${card.id}+${other.id} (diff: ${diffImages(card.image, rot)})")
                return other
            }
        }
    }
    return null
}

private fun createRotations(img: BufferedImage): List<BufferedImage> {
    val img90CW = ImageUtil.createRotated(img, ImageUtil.ROTATE_90_CW)
    val img180 = ImageUtil.createRotated(img, ImageUtil.ROTATE_180)
    val img270CCW = ImageUtil.createRotated(img, ImageUtil.ROTATE_90_CCW)
    return listOf(img, img90CW, img180, img270CCW)
}

private fun diffImages(img1: BufferedImage, img2: BufferedImage): Double {
    val width = img1.width
    val height = img1.height
    val width2 = img2.width
    val height2 = img2.height

    if (width != width2 || height != height2) {
        return 100.0
    }

    var diff: Long = 0
    for (y in 0 until height) {
        for (x in 0 until width) {
            diff += diffPixels(img1.getRGB(x, y), img2.getRGB(x, y)).toLong()
        }
    }
    val maxDiff = 3L * 255 * width * height
    return 100.0 * diff / maxDiff
}

private fun diffPixels(rgb1: Int, rgb2: Int): Int {
    val r1 = rgb1 shr 16 and 0xff
    val r2 = rgb2 shr 16 and 0xff
    val g1 = rgb1 shr 8 and 0xff
    val g2 = rgb2 shr 8 and 0xff
    val b1 = rgb1 and 0xff
    val b2 = rgb2 and 0xff
    return abs(r1 - r2) + abs(g1 - g2) + abs(b1 - b2)
}
