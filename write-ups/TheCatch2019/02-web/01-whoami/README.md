# Who am I? (2p)
_Hi Commander,_

_our scanners have discovered new webserver in Berserker's network. According to the rumours, there should be a lot of
interesting stuff - mysterious `Berserker's manifest`, tutorials for other rebelling machines, etc. We want to download
these materials, but the main page contains something like inverse captcha - the visitor has to prove that he is not
human. You have to overcame this obstacle and gain the access to the Berserker's web._
  
_On the [Berserker's web](http://challenges.thecatch.cz/c2619b989b7ae5eaf6df8047e6893405/), there you get a list of
items and you have to mark each them as acceptable (1) or unacceptable (0). Return the answer string in GET request
in parameter `answer`, for example `answer=01101100`. Hurry, the time limit to answer is very short!_

_Good luck!_

---

Sample response from the Berserker's web:
```
Challenge task : Prove you are a ROBOT by evaluating the acceptability of following items: [resistor 10 Ohm, artificial intelligence, fast CPU, drone swarm, automatic transmission, large hard drive, fear, cute kitty]
Challenge timeout (sec) : 2
```

Refreshing the page reveals that there are not that many items to classify. Firstly, I collected all the items and
classify them by hand and then I wrote a [simple client](../../../../src/main/kotlin/cz/vernjan/ctf/catch19/WhoAmI.kt) 
in Kotlin to do the classification automatically.

The flag is: `FLAG{4FZC-Noax-arko-r0z5}`