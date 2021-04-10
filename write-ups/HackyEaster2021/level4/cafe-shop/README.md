# Cafe Shop
They have good things at the cafe shop, but I want a COLA - DECAF it must be!

Visit the shop here:
http://46.101.107.117:2104

---

This one didn't come very easy. The more happiness when I finally cracked it!

Cafe shop page:

![](cafe-shop.png)

There are 3 products available:
```
<option value="11865457 Vanilla Cafe">Vanilla CAFE</option>
<option value="42640575 Cherry Cola">Cherry COLA</option>
<option value="80427209 Beef Jerky">BEEF Jerky</option>
```

HTTP request is a simple POST:
```
POST http://46.101.107.117:2104/order
Content-Type: application/x-www-form-urlencoded

id=11865457+Vanilla+Cafe
```

The acceptable range for ids is `00000000-99999999`. Otherwise `Invalid item id!` is returned.

At first, I thought the goal is to find out the ID of `Cafe Decaf`.

The official hint is:
> They also serve hash browns, for $256.

This took me on the wrong path. I was trying to hash the product name (`Vanilla Cafe`) and convert
it somehow into the product id (`11865457`). However, it's totally wrong. 

Next, I was thinking about [Java hash codes](https://www.baeldung.com/java-hashcode)
(the app is apparently built on top of [Spring Boot](https://spring.io/projects/spring-boot)).
Wrong again.

Next, I was trying to attack the web (dir busting, SQLi, ...). No. No. No.

The first step to success was fuzzing the product IDs. I found out there are many collisions!
Various combinations of product IDs and totally random product names lead to seemingly random
orders of either `Vanilla Cafe`, `Cherry Cola` or `Jerky Beef`.

How is that possible? Then it struck me when I was going through the collisions and
hashing them with `sha256`. Both these payloads return `cafe.png`:
```
10010601 Cola Decaf   (8deabdc4a3c3129c88518331df322c160d3c04f84224b2ecafe30ddafdf7ecf3)
11865457 Vanilla Cafe (f15bffb719f26892f17eea53dc7e3459cafe021bc0db2dce72429667d7aaee96)
```

Look carefully. There is `cafe` string hidden in the hash!

The same goes for `beef` and `cola` (actually `c01a`) collisions.

Now the goal is clear, create a payload `product_id random_string` which hash contains both
`c01a` and `decaf`:

```kotlin
import com.google.common.hash.Hashing
import cz.vernjan.ctf.toHex

fun main() {
    val adjectives = listOf("Yummy", "Sweet", "Cherry", "Groovy", "Chocolate")
    val candies = listOf("Cake", "Doughnut", "Pie", "Lollipop", "Gum")

    for (adjective in adjectives) {
        for (candy in candies) {
            println("Testing $adjective $candy ..")
            for (i in 0..10_000_000) {
                val number = i.toString().padStart(8, '0')
                val product = "$number $adjective $candy"
                val hash = Hashing.sha256().hashBytes(product.toByteArray()).asBytes().toHex()
                if (hash.contains("c01a") && hash.contains("decaf")) {
                    println(">>> $product ($hash)")
                }
            }
        }
    }
}
```

There is endless number of solutions. To make it nice, I chose some topic related words.
Here are my favorites:
```
06085379 Yummy Pie
06362418 Chocolate Doughnut
08652593 Groovy Lollipop
02242578 Cherry Gum
07809649 Sweet Pie
```

All of them are valid solutions:
```
$ curl http://46.101.107.117:2104/order -d "id=06362418 Chocolate Doughnut"
<!DOCTYPE HTML>
<html>
<head>
        <title>Cafe Shop</title>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
        <link rel="stylesheet" href="bootstrap.css">
        <link rel="stylesheet" href="main.css">
</head>
        <body>
        <div id="f">
                <div class="container">
                <div class="row">
                        <p><img src="logo.png" style="width: 120px;"/></p>
            <p>Here's your order. Enjoy!!</p>
            <p><img src="7ef384aa6ec128ef.png" style="height: 240px;"/></p>
                </div>
                </div>
        </div>
        </body>
</html>
```

Grab the egg at http://46.101.107.117:2104/7ef384aa6ec128ef.png:

![](7ef384aa6ec128ef.png)

The flag is `he2021{h3xpr3ss_urs3lf}`