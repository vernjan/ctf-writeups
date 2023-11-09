# VPN access

Ahoy, deck cadet,

a lot of ship systems is accessible only via VPN. You have to install and configure OpenVPN properly. Configuration file can be downloaded from CTFd's link VPN. Your task is to activate VPN and visit the testing page.

May you have fair winds and following seas!

Testing page is available at http://vpn-test.cns-jv.tcc.



---

The first challenge is easy. Just install [OpenVPN](https://openvpn.net/), import the config, connect and visit
http://vpn-test.cns-jv.tcc.

`FLAG{smna-m11d-hhta-ONOs}`

## Extra config for Ubuntu 22.4
- don't use Gnome Network Manager
- install these deb packages
  - `openvpn` and `openvpn-systemd-resolved` (for DNS resolution)
- add somewhere into `ctfd_ovpn.ovpn`:
    ```
    script-security 2
    up /etc/openvpn/update-systemd-resolved
    down /etc/openvpn/update-systemd-resolved
    down-pre
    ```
- run `sudo openvpn --config ctfd_ovpn.ovpn`
- useful tool `resolvectl`, we need to have DNS server for both `wlp0s20f3` and `tun0` (VPN)