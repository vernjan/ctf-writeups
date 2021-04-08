package cz.vernjan.ctf.he21

import com.auth0.jwt.JWT
import cz.vernjan.ctf.Resources
import cz.vernjan.ctf.decodeBaseUrl64

fun main() {
    val token = Resources.asString("he21/jwts.txt")
    printJwt(token)
}

fun printJwt(token: String) {
    val jwt = JWT.decode(token)
//    println("---")
//    println(jwt.header.decodeBaseUrl64())
//    println(jwt.claims.keys)
//    println(jwt.signature.decodeBaseUrl64())

    jwt.claims.keys.forEach {
        val claimValue = jwt.getClaim(it).asString()
        if (claimValue.contains(".")) {
            printJwt(claimValue)
        } else {
//            println("$it: $claimValue")
            if (it != "iss" && !it.startsWith("ct")) {
                println("$it: $claimValue")
            }
        }
    }
}