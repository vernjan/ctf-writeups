# DNS storage

Hi, packet inspector,

biggest surprise of the day is that the AI has started to use DNS as a storage for its own information. The data are
stored in TXT resource records in the zone `mysterious-delivery.tcc`. The zone is deployed on DNS servers
`ns1.mysterious-delivery.thecatch.cz` and `ns2.mysterious-delivery.thecatch.cz`.

Analyze content of zone and focus on any codes for our depot steel safes (AI has changed the access code and we hope it
is stored right in the DNS zone).

May the Packet be with you!

---

```
dig @ns1.mysterious-delivery.thecatch.cz  mysterious-delivery.tcc. ANY
```