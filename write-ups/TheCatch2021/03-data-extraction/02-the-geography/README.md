# The Geography

Hi Expert,

the web site accessible via `http://challenges.thecatch.cz/geography` has some kind of access protection based on used IP addres. Try to overcome this obstacle and find out what is behind it.

Good Luck!

---

Call the URL:
```
$ curl -i http://challenges.thecatch.cz/geography
HTTP/1.1 200 OK
..
Set-Cookie: theCatchSessionID=4n43ruvlmeknagslivijpg7k4k; expires=Mon, 18-Oct-2021 07:18:58 GMT; Max-Age=120; path=/; HttpOnly

Challenge task : Try to visit again from NL, Netherlands
Challenge timeout (sec) : 120
```

The task is to visit the URL from the Netherlands (in 120 seconds). The country changes
everytime you call the URL. There are many free VPNs which allow you
to change your country. Usually, the free VPNs support only a few big countries but that's
ok. Just hit the URL as many times (without any cookies), until you get one of the supported countries.
Then, connect via VPN and hit the URL one more time, but this time include the session cookie:
```
$ curl -i -H 'Cookie: theCatchSessionID=4n43ruvlmeknagslivijpg7k4k' http://challenges.thecatch.cz/geography
HTTP/1.1 200 OK
..
Set-Cookie: theCatchSessionID=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0; path=/

FLAG{OlFY-P2U0-86he-qU4q}%
```