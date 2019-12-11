# HV19.H3 Hidden Three
_Not each quote is compl_

---

_Note: The challenge was released on [Day 11](../day11/README.md) and it was tagged as PENETRATION TESTING._

At first I was trying (No)SQL injections into `/fsja/register`, `/fsja/login` or even into JWT token.
Found nothing.

The next I ran a port scan on http://whale.hacking-lab.com/:
```
$ nmap whale.hacking-lab.com
Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-10 18:19 CST
Nmap scan report for whale.hacking-lab.com (80.74.140.188)
Host is up (0.028s latency).
rDNS record for 80.74.140.188: urb80-74-140-188.ch-meta.net
Not shown: 993 filtered ports
PORT     STATE  SERVICE
17/tcp   open   qotd
22/tcp   open   ssh
80/tcp   closed http
443/tcp  closed https
2222/tcp closed EtherNetIP-1
4444/tcp closed krb524
5555/tcp closed freeciv

Nmap done: 1 IP address (1 host up) scanned in 49.19 seconds
```

Port 17 and service `qotd` took my attention.
According [Wiki](https://en.wikipedia.org/wiki/QOTD), QOTD is _Quote of the Day_ service.
See, it matches the challenge description - _Not each **quote** is compl_.

Ok, let's try:
```
$ nc whale.hacking-lab.com 17
H
```
Hm, not much, but it could be the first letter of the flag. I tried again but always received 
the same letter `H`.

I returned to the challenge a bit later and, to my pleasure, this time I received `V`!
That really looks like a flag being broad-casted letter by letter.

Apparently a new letter is broad-casted once per hour. We need some automation.
I launched a new EC2 VM and executed using `nohup`:
```shell script
while true; do
  nc whale.hacking-lab.com 17 >> flag.txt
  sleep 3600
done
```
And waited ..