# DNS storage

Hi, packet inspector,

biggest surprise of the day is that the AI has started to use DNS as a storage for its own information. The data are
stored in TXT resource records in the zone `mysterious-delivery.tcc`. The zone is deployed on DNS servers
`ns1.mysterious-delivery.thecatch.cz` and `ns2.mysterious-delivery.thecatch.cz`.

Analyze content of zone and focus on any codes for our depot steel safes (AI has changed the access code and we hope it
is stored right in the DNS zone).

May the Packet be with you!

---

Let's start with fetching all (`ANY`) zone records:

```
$ dig @ns1.mysterious-delivery.thecatch.cz mysterious-delivery.tcc. ANY +noall +answer
mysterious-delivery.tcc. 86400  IN      SOA     ns1.mysterious-delivery.tcc. hostmaster.ns1.mysterious-delivery.tcc. 2022100101 604800 86400 2419200 86400
mysterious-delivery.tcc. 86400  IN      RRSIG   SOA 8 2 86400 20221027100841 20220927100841 65089 mysterious-delivery.tcc. t+41dUUEePq9q66faNOiF7IpdPbCiWWfqwPhjNfqprT521mIRpu9toZP TYjuu7vB2HqE12/kKHlNj5htcmAyeTdRS4Yj+XfmasJ5akynPd47/ToC PVVP0QwKRn4q3VeflIHDjsD3ReWMPr2Qm1yG55g1pP6OrGwQYCxIOZO4 QlAomqnDyzdNiOUz6xLEfajdMwZXT863oB/NmyxyTQxX7iY8xcYSpG1l U65Tq58gmSMQE4ChMh3tD0FxGsqXQfIRj4vfCaVljXDrTnVkesePGTng R0CSaZCbqxtJqNsLX7hKozfLWlCl4xwtFhJtkOzR8OSk6aNEIOmzK8AZ bOgj4g==
mysterious-delivery.tcc. 86400  IN      NS      ns1.mysterious-delivery.thecatch.cz.
mysterious-delivery.tcc. 86400  IN      NS      ns2.mysterious-delivery.thecatch.cz.
mysterious-delivery.tcc. 86400  IN      RRSIG   NS 8 2 86400 20221027100841 20220927100841 65089 mysterious-delivery.tcc. 38BBMrh2vLNUlmrYfcZ/P9qh6UZpMloKOMaY8W67bMpLAA1+s7kRCgzM oBRsGoASHSGhO9a60tQA5caGDa9CgiJOPrlEHgHKhkBQEA8r5RGdl0oc 8dK5iVP4lhgUqhxVeyzYoyXm9Evtk6hDpNQVLkPjI87zkOBHIPK8a3jB i5Pvdig5ElCtSqstS4bNViyq6sTafnfKowIFXU3S46gq6yXzNLXEdw+t Zl9Jw/F499fiiduou3Gp+AOa0Dn0/A58urtS/v1w1ojEOeZPWEX7yfP5 ObgfFKqo28pBD26AmHAuNqcuceYkH6aRsvuAIKf2eJy+dRuM2aXJ07rm 4FsL8g==
mysterious-delivery.tcc. 86400  IN      NSEC    www.customer-service.mysterious-delivery.tcc. NS SOA RRSIG NSEC DNSKEY
mysterious-delivery.tcc. 86400  IN      RRSIG   NSEC 8 2 86400 20221027100841 20220927100841 65089 mysterious-delivery.tcc. 4QM+aji7fcVlnH6xPZyl23o+LUSWchP99PAV46Xz6IexIiA8fFPvBwMg OWJQB/iAwu2FPi50WyrPoQnvgjA2Lgqav2GXQTF4kuB2G7s/X9WCx1Bi S3kiVzmoYJxX8a+ZjU35DGM6aTsVRo6qcWbG4KGAFS38RoDVfKH/69g4 GvRFEubNfH+YCa/e583WBwmqIUa7k0+iXsIJ1skIASpIwoc9kytNSpKN 8DOgjprEwJY1mZFGZTTRMmmYoKkRcGa5MfL7k7OEti3jsL+Oj/NIcXcU UjFFiplzVWX0dWCLGRuvEU+xGKkRUnv9HEQSi/kPCKmax4cgo3lFhItt 3ohpJw==
mysterious-delivery.tcc. 86400  IN      DNSKEY  257 3 8 AwEAAaGDAm8Fav1uO0yT/rwq3G+5uFyfs0Mmq0BrwOvvkogKVnoAuMtq yl6oE1v+GfG7mwEdWev8xjBqLntsxFum17l0NFc8+COlFMG938uV6PWA sz+tvohtcoxhz8fCcTUpNWEv9tjOQQfiIUL3icpCiXZw/2jQB+VpT2fF TnoNoHItvPU+2hnGHHzWDRUNvnWookE/q6kOUKxmh2OAEeYYxAYa2Phw nEifJH+PUwYMzSrDsIbslpER9Q98mvjmbz+mO4P7subZvV0tSBZYj9fg 0BROe10li4tU2npizp0pKdP0+RwkXUfyP0hxo/R6nXDlhsFVea3KpwQP neRFaXpB4CRVGh/WFkvsqF7Gt0mu7Tnvr2QrpBTQefJFg8oLlcRItpGu SVuEEWuYnWiSEHwUqIVyq0s9PesHRPWP1gWMIADkVpwN1Qg2xLWEHjAQ 7QASZ4OPkvim58MxwZmXrmAVot/kGoz8hj6PLlJOYaX5txPp60egdnJK IALT7znkE2JV9UtI873wnnghIfDVDd0tR2tDeDyUSK5vfFyD9k6QJuse /QxFybx40y9plqR8QjxOsEJqFy/BYaGGDL/RE7Gfuj+YC5znlc5g9mYd 98QTola9bI/TA6Eacez+//uk47vq5rQNAhyobb9YwPJLTseR+81eVZWu iava9ZQqO5qaWL09
mysterious-delivery.tcc. 86400  IN      DNSKEY  256 3 8 AwEAAeQRCIW3223GKo3Y0DEltzP6DrbQPlP12Uk/XIzEW3KyeKbc2564 0JNzeo6FsYDnHnvZ8UAzbOZ7xVS14Pj9ekGzSLtL10AGF2Witwo8afft KwYRpzsAafNXvSgh2SebKshkmmtXVSDASU/xgKlG/XDvclHLRd626VtV bdFbsUlNncNg122oO3RL7wDGewQFGX4byJfcNtbHpJn1dhFrC7It3bu0 09w8cvgiCg6/oQ4We/0D3BVWZPnzS04FhwpAtIcqYm9GfIgzk54/wN9C 4flCdLBykdXGo8us/DeLtJfh+ler03HsRkMbQQoIuo2wwigoENyXNYWb kJj/egQjN/E=
mysterious-delivery.tcc. 86400  IN      RRSIG   DNSKEY 8 2 86400 20221027100841 20220927100841 22312 mysterious-delivery.tcc. HCJmqUzLd/TmjZCqrIV4rv28mgi9+Xq09tIqJbwLSr6jwqid+8fnnITc nRw7LExW+M6BY31d//mz+ogHT0plS1DF9OnIPGKdKSmVRJrnbHq9VEtX ipAUuTCJbj2jPGbamoeNvwk63hz/DeOM10JHRVw+RSSuPhFRS/mfcbLb GiDw8foSjwUvmQv4dk/oKneMrxEopMwXqETvn4zupdweD+DWRWWZPF5V /Dt/72ip4df56on0XmQucKFztGC8VpDRcoW/76i9sz+t4an0XT48+JsW qhySFl/ZPbcollI0znlHIz6L90HZVZ9r8ocdUhkDR5ELTUHl1kNIfQq4 qOBq3bnS9HE/7ZTay4YVXEDMgrXjzcPd4I4dRgs9Mhop/Y9/FHP+IR+f LLgGE1K6LU3a4EqgsTCiKyXakWxG1Qy6PZETs4EAln5Xj/aXdHKWh0TQ es/YAtHZndO7fsxL+NlTyVi3uyni5TuTuHCYiwgPmRvFKXmO3iDrnhs1 ZZTcEUbiZ8LKAk06wjGos64A72SuTeZFCzK2fphd6LWVRbenKRNFkqS2 rJCZgixu5jF8SD4hwZXpUNxKmST+JYuQRR88ei38dAfbMcmOgPAYIKeg wojmW3B1zy38np+/SEplUqyeZiTKl/TNkLFvRu9LYX2tTVcxqtbj1dZv g/OaoqsZReQ=
mysterious-delivery.tcc. 86400  IN      RRSIG   DNSKEY 8 2 86400 20221027100841 20220927100841 65089 mysterious-delivery.tcc. tv+eQwT8IOhnFtpMx9XYMdJ8/WQ8Y7zMcdHrkXZs9k5qTqyvwNqYx3sx RnCWpHFNjIk2056cEOQZR9VsAnkR8xD7jqKsLb8HlJMTbjdvJNFp3TcB bPd+RJk4Al9HvV/3Y8O04gakAlh27JWix+5tmwxXjacoZ1erg4eijZEH ILlz9fL23DZ7DkstYVORiFW5eWSGnu1S9p3ePJ8ZWiNkTntKDf7L+KkR Zhb6kN3+4Ijkg6jZ9U60Vq6GRugJU1SAYSK0lVpSvPuGzXHU7yt9Od2c 8dnzzWp1wUkq+1CFeENJtgiihRFXASR7VjZu2Gw3K9PM50ktEuc8eyjf 4zQDpQ==
```

My eye was caught by the `NSEC` record:

```
mysterious-delivery.tcc. 86400  IN      NSEC    www.customer-service.mysterious-delivery.tcc. NS SOA RRSIG NSEC DNSKEY
```

Let's query `www.customer-service.mysterious-delivery.tcc.`:

```
$ dig @ns1.mysterious-delivery.thecatch.cz www.customer-service.mysterious-delivery.tcc. ANY +noall +answer
..
www.customer-service.mysterious-delivery.tcc. 86400 IN NSEC delay-generator.mysterious-delivery.tcc. CNAME RRSIG NSEC
..
```

Keep digging:

```
$ dig @ns1.mysterious-delivery.thecatch.cz delay-generator.mysterious-delivery.tcc. ANY +noall +answer
..
delay-generator.mysterious-delivery.tcc. 86400 IN NSEC delivery-team-hq-0000b.mysterious-delivery.tcc. CNAME RRSIG NSEC
..
```

The chain seems to be long. Time for automation:

```shell
#!/bin/bash

dns_zone="delay-generator.mysterious-delivery.tcc."

while true; do
	answer="$(dig @ns1.mysterious-delivery.thecatch.cz "$dns_zone" ANY +noall +answer)"
	
	dns_zone="$(echo "$answer" | grep -o 'IN\sNSEC\s[^ ]*' | cut -c 9-)"
	txt="$(echo "$answer" | grep -o 'IN\sTXT\s.*' | cut -c 8-)"
	
	echo "$dns_zone --> $txt"

	sleep 0.1
done
```

See full script output in [dns_dump.txt](dns_dump.txt).

The interesting TXT record is at `depot-secret-upon-flag.mysterious-delivery.tcc.`:

```
secret code for steel safe is: RkxBR3tZcjMxLVhvWEUtNEZxOC02UElzfQ==
```

Decode base64:

```
$ echo RkxBR3tZcjMxLVhvWEUtNEZxOC02UElzfQ== | base64 -d
FLAG{Yr31-XoXE-4Fq8-6PIs}
```