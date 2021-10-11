# The Motivation

Hi Expert,

one of the discovered servers on IP `78.128.216.7` was somehow used to increase the motivation and morale of people. At least the chief archaeologist thinks so. Have a closer look.

Good Luck!

---

Start with `nmap` port scan:
```
$ nmap  78.128.216.7
Starting Nmap 7.80 ( https://nmap.org ) at 2021-10-15 21:17 CEST
Nmap scan report for 78.128.216.7
Host is up (0.050s latency).
Not shown: 998 closed ports
PORT      STATE    SERVICE
17/tcp    open     qotd
65000/tcp filtered unknown

Nmap done: 1 IP address (1 host up) scanned in 9.41 seconds
```

Port 17 ([QOTD](https://www.gkbrk.com/wiki/qotd_protocol/)) looks interesting.
We can easily connect with `nc`:
```
$ nc 78.128.216.7 17
* Between two evils, I generally like to pick the one I never tried before. - Mae West
```

On each connect, you get a different quote. Let's get a few of them:
```
for i in {0..100}; do echo | nc 78.128.216.7 17 ; done
* To get what you want, deserve what you want. Trust, success, and admiration are earned. - Charlie Munger
* Almost everything will work again if you unplug it for a few minutes, including you. - Anne Lamott
* The busy man is least busy with living. - Seneca
* We already know what we need to do. - United States Navy Seal and Rhodes Scholar Eric Greitens
...
```

I noticed one of the quotes is:
> Once a correct sequence of connection attempts is received, the firewall rules are dynamically modified to allow the host. Sequence of three ports is 65000 + {DNS, LDAP, Syslog). Btw. look at 65000 again.  - The Catcher

Ok, let's do that. I created a bash script `ports.sh`:
```
nc -v 78.128.216.7 65053
nc -v 78.128.216.7 65389
nc -v 78.128.216.7 65514
nmap 78.128.216.7 -p 65000 # Not required, just to show the port is now open.
nc 78.128.216.7 65000
```

Run it:
```
$ ./ports.sh
nc: connect to 78.128.216.7 port 65053 (tcp) failed: Connection refused
nc: connect to 78.128.216.7 port 65389 (tcp) failed: Connection refused
nc: connect to 78.128.216.7 port 65514 (tcp) failed: Connection refused
Starting Nmap 7.80 ( https://nmap.org ) at 2021-10-15 21:33 CEST
Nmap scan report for 78.128.216.7
Host is up (0.015s latency).

PORT      STATE SERVICE
65000/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 1.10 seconds
FLAG{qC6Z-dQS7-4qoC-tR1m}
```