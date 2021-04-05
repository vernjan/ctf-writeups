# Run Me, Baby!
This one's easy, ain't it? Just run the `.class` file. Hope you like Java!

[runme.class](runme.class)

---

Alright, let's run it:
```
$ java runme
Error: Could not find or load main class runme
Caused by: java.lang.NoClassDefFoundError: groovy/lang/Script 
```

Looks like a [Groovy](https://groovy-lang.org/) script.
Download and unzip Groovy, and then add it to classpath:
```
$ java -cp "groovy-3.0.7/lib/*:." runme
The flag is: he2021{isnt_17_gr00vy_baby?}
```

The flag is `he2021{isnt_17_gr00vy_baby?}`