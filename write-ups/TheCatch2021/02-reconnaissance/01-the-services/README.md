# The Services

Hi Expert,

examine the services on new discovered server `78.128.216.6` in order to have a comprehensive picture.

Good Luck!

---

Scan for open ports with _nmap_:
```
$ nmap 78.128.216.6
Starting Nmap 7.80 ( https://nmap.org ) at 2021-10-12 21:35 CEST
Nmap scan report for 78.128.216.6
Host is up (0.023s latency).
Not shown: 996 closed ports
PORT      STATE SERVICE
2021/tcp  open  servexec
2022/tcp  open  down
4445/tcp  open  upnotifyp
58080/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 9.14 seconds
```

## Service :2021 (FTP)
```
$ nc 78.128.216.6 2021
220-FLAG4{YtRk1rMi00OXlXfQ==}
220
hello
530 Please login with USER and PASS.
```

This is an FTP server (judging based on the responses).

## Service :2022 (SSH)
```
$ nc 78.128.216.6 2022
SSH-2.0-FLAG3{czcV} -------------------
^[[A^C
```

SSH server, and we got 2 flag parts. We can assume other services will somehow be hiding
2 more flag parts.

There is also an obvious pattern:
- `2021` is FTP. Standard port for FTP is `21`.
- `2022` is SSH. Standard port for SSH is `22`.

## Service :4445 (Samba)
We can guess `4445` is Samba (`445`). I was struggling a bit to find the flag on this port.
I tried to connect with `smbclient` but couldn't find anything. The correct approach is
to use detailed nmap scan:
```
$ nmap -p 4445 -sV 78.128.216.6
Starting Nmap 7.80 ( https://nmap.org ) at 2021-10-13 07:45 CEST
Nmap scan report for 78.128.216.6
Host is up (0.016s latency).

PORT     STATE SERVICE     VERSION
4445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: FLAG2{M3LV})
Service Info: Host: 9C88B168B9B4
```

>-`sV`: Probe open ports to determine service/version info

## Service :58080 (Apache HTTP server)
The last flag part is hidden on `58080`. `8080` is usual for HTTP servers.
I accessed `http://78.128.216.6:58080` using a web browser. In HTTP response header, there
is `Server: FLAG1{RkxBR3tZcm}`.

## Flag

We got all flag parts:
- `FLAG1{RkxBR3tZcm}`
- `FLAG2{M3LV}`
- `FLAG3{czcV}`
- `FLAG4{YtRk1rMi00OXlXfQ==}`

```
$ echo 'RkxBR3tZcmM3LVczcVYtRk1rMi00OXlXfQ==' | base64 -d
FLAG{Yrc7-W3qV-FMk2-49yW}
```