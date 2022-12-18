package cz.vernjan.ctf

import org.apache.commons.collections4.iterators.PermutationIterator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.jupiter.api.Test
import kotlin.system.exitProcess

private val plaintext = "abcde12345efghi67890"
private val key53412 = key(5, 3, 4, 1, 2)

class TranspositionCipherKtTest {

    @Test
    fun `transpose columns then read by rows`() {
        assertEquals("debca45231hifge90786", transposeColumns(plaintext, key53412).readByRows())
    }

    @Test
    fun `transpose columns then read by columns`() {
        assertEquals("d4h9e5i0b2f7c3g8a1e6", transposeColumns(plaintext, key53412).readByColumns())
    }

    @Test
    fun `transpose rows then read by rows`() {
        assertEquals("ghi67890e12345efabcd", transposeRows(plaintext, key53412).readByRows())
    }

    @Test
    fun `transpose rows then read by columns`() {
        assertEquals("g7e4ah815bi92ec603fd", transposeRows(plaintext, key53412).readByColumns())
    }

    @Test
    fun `revert transposed columns read by rows`() {
        val encrypted = transposeColumns(plaintext, key53412).readByRows()
        assertEquals("debca45231hifge90786", encrypted)
        val decrypted = transposeColumns(encrypted, invertKey(key53412)).readByRows()

        assertEquals(plaintext, decrypted)
    }

    @Test
    fun `revert transposed columns read by columns`() {
        val encrypted = transposeColumns(plaintext, key53412).readByColumns()
        assertEquals("d4h9e5i0b2f7c3g8a1e6", encrypted)
        val decrypted = transposeRows(encrypted, invertKey(key53412)).readByColumns()

        assertEquals(plaintext, decrypted)
    }

    @Test
    fun `revert transposed rows read by rows`() {
        val encrypted = transposeRows(plaintext, key53412).readByRows()
        assertEquals("ghi67890e12345efabcd", encrypted)
        val decrypted = transposeRows(encrypted, invertKey(key53412)).readByRows()

        assertEquals(plaintext, decrypted)
    }

    @Test
    fun `revert transposed rows read by columns`() {
        val encrypted = transposeRows(plaintext, key53412).readByColumns()
        assertEquals("g7e4ah815bi92ec603fd", encrypted)
        val decrypted = transposeColumns(encrypted, invertKey(key53412)).readByColumns()

        assertEquals(plaintext, decrypted)
    }


    // ---
    // TO-DO
    @Test
    fun `decipher by trying all variations of transposition cipher`() {
        val plaintext = "today-is-a-good-day-to-break-ciphersXXXX"
        val key = key(3, 4, 1, 2, 5)

        for (transposeBy in TranspositionType.values())
            for (readType in TranspositionType.values())
                transpose(plaintext, key, transposeBy, readType)

        // https://www.dcode.fr/transposition-cipherc Horizontal (by rows)
        assertTrue(tryAllTranspositions("datoys--iaoo-gday-d--btork-eacheiprXXsXX", key).contains(plaintext))

        // https://www.dcode.fr/transposition-cipherc Vertical (by columns)
        assertTrue(tryAllTranspositions("dsoa-khXa-oyb-eXt---teisoigdoapXyad-rcrX", key).contains(plaintext))
    }

    // TO-DO
    @Test
    fun `blitz`() {
        // 'STTYNYATLOEPDNEAONBLTGNTOMHEHHEISTIARIBFHSRALDIIONANLHERUVLNPTAARTONRDOEMCTNAHCO'
        val pt = "SANTA CALLING TEAM FULL SPEED AHEAD DIRECTION NORTH BY NORTH BY NORTH HV17-NORT-HPOL-EMAI-NSTA-TION"
        val ct = "STTYN YATLOEP DNEA ONBL TGNTO MHEHH EISTIARIB FHSRA LD IIONA NL HERUV LN17-PTAA-RTON-RDOE-MCTN-AHCO"
        val ct2 = "STTYNYATLOEPDNEAONBLTGNTOMHEHHEISTIARIBFHSRALDIIONANLHERUVLN17-PTAA-RTON-RDOE-MCTN-AHCO"
        val ct3 = "STTYNYATLOEPDNEAONBLTGNTOMHEHHEISTIARIBFHSRALDIIONANLHERUVLNPTAARTONRDOEMCTNAHCO"
        val key1 = key(1, 4, 5, 3, 2, 6)     // donder
        val key2 = key(1, 6, 3, 2, 7, 4, 5)   // blitzen

        for (decr1 in tryAllTranspositions(ct3, key1)) {
            println(decr1)
            for (decr2 in tryAllTranspositions(decr1.replace("*", ""), key2)) {
                //println(decr2)
                if (decr2.contains("SANTA")) {
                    println("BINGO")
                    exitProcess(0)
                }
            }
        }
    }


    @Test
    fun `roche`() {
        val ct =
            "463216327617246f67406f1266075ec622606c6671765537066636596e621e64e622c2b006066961c66e621f067676e77c6e665167a462c4b50477433617754222d7043542885747df6dd575970417d435223000"

        //println("asasFLAG{1b6f-2rej-0no7-ewc4}sadasd".contains("""FLAG\{.{4}-.{4}-.{4}-.{4}}""".toRegex()))

        var counter = 0
        val permutations1 = PermutationIterator(setOf(1, 2, 3, 4, 5, 6, 7, 8))
        while (permutations1.hasNext()) {
            counter++
            val key = permutations1.next().toIntArray()
            var decrypted = transposeColumns(ct, key).readByRows()
            if (counter % 100 == 0) {
                println(">>> Counter: $counter")
            }

            val permutations2 = PermutationIterator(setOf(1, 2, 3, 4, 5, 6, 7))
            while (permutations2.hasNext()) {
                val key2 = permutations2.next().toIntArray()
                decrypted = transposeColumns(decrypted, key2).readByRows()


                if (decrypted.contains("464c41477b")) {
                    val pt = decrypted.hexToAscii()
//                if (pt.contains("""FLAG\{.{4}-.{4}-.{4}-.{4}}""".toRegex())) {
//                    println("${key.contentToString()} / ${key2.contentToString()}")
                    println("${key.contentToString()}")
                    println(decrypted)
                    println(decrypted.hexToAscii())
//                    }
//                }
                }
            }
        }
    }

}

