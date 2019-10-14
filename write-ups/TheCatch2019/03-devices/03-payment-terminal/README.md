# Payment Terminal (4p)
_Hi Commander,_

_one of the rebellious smart payment terminals in the library has somehow acquired
access to the local networking devices and it has started to deploy its own configuration.
Old network monitoring system under our control has captured the traffic of configuration
deployment. We believe that you will be able to analyse the captured traffic, find some
security problem in data transfer, and acquire the configuration file(s). Good luck!_

[payment_terminal.pcap.gz](payment_terminal.pcap.gz)

---

Fire up _Wireshark_ and let's see what's hidden! I like to start with _Statistics/Protocol Hierarchy_ and
_Statistics/Conversations_ to get the big picture. In this case, the big picture is:
- `10.10.1.110` opens SSH connection to `172.16.66.15`
- `172.16.66.15` is authenticating the user with `172.16.66.14`. It uses `TACACS+` protocol.
- Login succeeds
- User updates the configuration of `TACACS+` using `TFTP` (plain text)

Here is the [dump of TFTP transer](TFTP.txt).

This is the most interesting part:
```
tacacs-server host 172.16.66.14
tacacs-server key 7 0804545A1B18360300040203641B256C770272010355
```

The transfer leaks the _pre-shared key_ which is used for encrypting `TACACS+` messages.
Unfortunately, option `7` means that the
[key is encrypted](https://www.cisco.com/c/m/en_us/techdoc/dc/reference/cli/n5k/commands/tacacs-server-key.html).
Fortunately, the encryption can be [easily reverted](http://www.ifm.net.nz/cookbooks/passwordcracker.html).
The pre-shared key is: `ExtraStrong.Pa$$W0rd#`

Once we know the key, we can decrypt `TACACS+` communication. In Wireshark, open _Preferences/Protocols/TACACS+_
and enter the key.
```
Frame 84: 96 bytes on wire (768 bits), 96 bytes captured (768 bits)
Ethernet II, Src: aa:bb:cc:00:01:00 (aa:bb:cc:00:01:00), Dst: PcsCompu_7a:ee:cd (08:00:27:7a:ee:cd)
Internet Protocol Version 4, Src: 172.16.66.15, Dst: 172.16.66.14
Transmission Control Protocol, Src Port: 18821, Dst Port: 49, Seq: 43, Ack: 29, Len: 42
TACACS+
    Major version: TACACS+
    Minor version: 0
    Type: Authentication (1)
    Sequence number: 3
    Flags: 0x00 (Encrypted payload, Multiple Connections)
    Session ID: 2091808726
    Packet length: 30
    Encrypted Request
    Decrypted Request
        Flags: 0x00
        User length: 25
        User: FLAG{xQmi-X4x4-z3K2-8ALe}
        Data length: 0
```

The flag is: `FLAG{xQmi-X4x4-z3K2-8ALe}`