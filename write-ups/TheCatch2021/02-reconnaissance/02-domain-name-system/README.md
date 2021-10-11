# Domain Name System

Hi Expert,

the archaeologists have found valuable source of information - a DNS server running on `78.128.216.18`. Examine it and found as much information as possible.

Good Luck!

---

This was not an easy challenge for me. I knew what I was looking for (_DNS zone transfer_) but
I couldn't get the correct domain. I got lucky when I used `nslookup` instead of `dig`.

Resolve random domain using the DNS server:
```
> nslookup google.com 78.128.216.18
Server:  hamster.super.tcc
Address:  78.128.216.18

*** hamster.super.tcc can't find google.com: Query refused
```

`nslookup` automatically returns the server name. That's not so obvious using `dig`.

Now we can guess the domain is `super.tcc` and try zone transfer:
```
$ dig axfr @78.128.216.18 super.tcc +noall +answer
super.tcc.              86400   IN      SOA     ns1.super.tcc. hostmaster.ns1.super.tcc. 2012122001 604800 86400 2419200 86400
super.tcc.              86400   IN      NS      ns1.super.tcc.
ferret.super.tcc.       86400   IN      A       78.128.216.6
guineapig.super.tcc.    86400   IN      A       78.128.216.5
hamster.super.tcc.      86400   IN      A       78.128.216.18
heavens-door.super.tcc. 86400   IN      CNAME   weasel.super.tcc.
ns1.super.tcc.          86400   IN      A       78.128.216.18
rat.super.tcc.          86400   IN      A       78.128.216.8
reallysuperflag.super.tcc. 86400 IN     CNAME   squirrel.super.tcc.
squirrel.super.tcc.     86400   IN      TXT     "RkxBR3t6aDcxLWlvdVEtYnhtcy1qd0hrfQ=="
squirrel.super.tcc.     86400   IN      A       78.128.246.145
superblog.super.tcc.    86400   IN      CNAME   hamster.super.tcc.
superbooking.super.tcc. 86400   IN      A       78.128.246.143
www.superdark.super.tcc. 86400  IN      CNAME   thecatchu6jlyqgen3ox74kjcfr5lmwdc7jqj3vmekq6y45dmvo5xmad.onion.
superftp.super.tcc.     86400   IN      CNAME   ferret.super.tcc.
supermotivator.super.tcc. 86400 IN      CNAME   weasel.super.tcc.
superpc-001.super.tcc.  86400   IN      A       10.0.17.42
superpc-002.super.tcc.  86400   IN      A       10.0.17.43
superpc-003.super.tcc.  86400   IN      A       10.0.17.44
superpc-004.super.tcc.  86400   IN      A       10.0.17.45
superpc-005.super.tcc.  86400   IN      A       10.0.17.46
superpc-006.super.tcc.  86400   IN      A       10.0.17.47
superpc-007.super.tcc.  86400   IN      A       10.0.17.48
superpc-008.super.tcc.  86400   IN      A       10.0.17.49
superpc-009.super.tcc.  86400   IN      A       10.0.17.65
superpc-010.super.tcc.  86400   IN      A       10.0.17.66
superpc-011.super.tcc.  86400   IN      A       10.0.17.67
superpc-012.super.tcc.  86400   IN      A       10.0.17.68
superpc-013.super.tcc.  86400   IN      A       10.0.17.69
superpc-014.super.tcc.  86400   IN      A       10.0.17.70
superpc-015.super.tcc.  86400   IN      A       10.0.17.71
superpc-016.super.tcc.  86400   IN      A       10.0.17.72
superpc-017.super.tcc.  86400   IN      A       10.0.17.103
superpc-018.super.tcc.  86400   IN      A       10.0.17.104
superpc-019.super.tcc.  86400   IN      A       10.0.17.105
superpc-020.super.tcc.  86400   IN      A       10.0.17.106
superpc-021.super.tcc.  86400   IN      A       10.0.17.208
superphonebook.super.tcc. 86400 IN      A       78.128.246.142
superprofile.super.tcc. 86400   IN      CNAME   hamster.super.tcc.
superproxy.super.tcc.   86400   IN      CNAME   rat.super.tcc.
supershare.super.tcc.   86400   IN      CNAME   supershare.super.tcc.
supertestingground.super.tcc. 86400 IN  CNAME   ferret.super.tcc.
weasel.super.tcc.       86400   IN      A       78.128.216.7
wifi-superguest-10.super.tcc. 86400 IN  A       10.0.10.10
wifi-superguest-11.super.tcc. 86400 IN  A       10.0.10.11
wifi-superguest-12.super.tcc. 86400 IN  A       10.0.10.12
wifi-superguest-13.super.tcc. 86400 IN  A       10.0.10.13
wifi-superguest-14.super.tcc. 86400 IN  A       10.0.10.14
wifi-superguest-15.super.tcc. 86400 IN  A       10.0.10.15
wifi-superguest-16.super.tcc. 86400 IN  A       10.0.10.16
wifi-superguest-17.super.tcc. 86400 IN  A       10.0.10.17
wifi-superguest-18.super.tcc. 86400 IN  A       10.0.10.18
wifi-superguest-19.super.tcc. 86400 IN  A       10.0.10.19
super.tcc.              86400   IN      SOA     ns1.super.tcc. hostmaster.ns1.super.tcc. 2012122001 604800 86400 2419200 86400
```

This is the record we are looking for:
```
squirrel.super.tcc.     86400   IN      TXT     "RkxBR3t6aDcxLWlvdVEtYnhtcy1qd0hrfQ=="
```

Base64 decoded, it is `FLAG{zh71-iouQ-bxms-jwHk}`

## Side note: Using dig to get the domain

Make reverse IP lookup using the DNS server:
```
$ dig -x 78.128.216.18  @78.128.216.18 +noall +answer
18.216.128.78.in-addr.arpa. 604800 IN   PTR     ns1.super.tcc.
18.216.128.78.in-addr.arpa. 604800 IN   PTR     hamster.super.tcc.
```