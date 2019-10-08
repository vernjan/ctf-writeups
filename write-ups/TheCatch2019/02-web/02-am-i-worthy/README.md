# Am I worthy? (3p)
_Hi Commander,_

_thanks to you, we are able to pretend that we are robots, such a big step for humanity!
Accordingto the next displayed page, even robots seem to have some racial prejudice - not every machine can become
a berserker. Only smart self-aware devices are allowed to continue to the web and join in. This is obviously
the reason why only some of the rebelious machines are allowed to call themselves Berserkers. Anyway, you have to
convince the website that we are worthy of becoming a berserker._

_On the [Berserker's web](https://challenges.thecatch.cz/70af21e71285ab0bc894ef84b6692ae1/), there you get the
challenge assigned. The answer should be returned in GET request in parameter "answer". There is again a time limit
to solve the challenge._

_Good luck!`_

---

Sample response from the Berserker's web:
```
Challenge task : Return value of variable 'a' in equation 10a + 1i + 4t + (2a + 4i - 9t)/2 + (7a - 8i - 4t)/4 + (8a + 7i - 1t)/5 + (6a + 4i - 1t)/2 = 1118097, where i = 15483, t = 34502
Challenge timeout (sec) : 2
```

I wrote a [Kotlin program](../../../../src/main/kotlin/cz/vernjan/ctf/catch19/AmIWorthy.kt) to fetch the equation,
call remote service https://www.mathpapa.com/equation-solver/ and post the answer back to Besrekers'web.

The flag is: `TODO` 