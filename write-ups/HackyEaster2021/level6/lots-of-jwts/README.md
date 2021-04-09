# Lots of JWTs
So many JWTs! What do they hide?

[jwts.txt](jwts.txt)

---

I decoded the token at https://jwt.io/. It contains more tokens. And those tokens contain another tokens...

This is job for a small utility program:
```kotlin
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
```

It recursively decodes all the tokens and prints the claims which are not `iss` or `ct*`.

The output is:
```
i: he202
iv: f_js0
v: n_t0k
iii: nty_0
vi: k3nZ}
ii: 1{pl3
```

Rearrange it:
```
i: he202
ii: 1{pl3
iii: nty_0
iv: f_js0
v: n_t0k
vi: k3nZ}
```

The flag is `he2021{pl3nty_0f_js0n_t0kk3nZ}`