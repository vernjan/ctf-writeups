package cz.vernjan.ctf.he21

import com.auth0.jwt.JWT
import cz.vernjan.ctf.Resources

fun main() {
    val token = Resources.asString("he21/jwts.txt")
    printJwt(token)
}

fun printJwt(token: String) {
    val jwt = JWT.decode(token)
    jwt.claims.keys.forEach { key ->
        val claimValue = jwt.getClaim(key).asString()
        if (claimValue.contains(".")) {
            printJwt(claimValue)
        } else {
            if (key != "iss" && !key.startsWith("ct")) {
                println("$key $claimValue")
            }
        }
    }
}