# HV20.12 Wiener waltz

## Introduction
_During their yearly season opening party our super-smart elves developed an improved usage of the well known RSA crypto algorithm. Under the "Green IT" initiative they decided to save computing horsepower (or rather reindeer power?) on their side. To achieve this they chose a pretty large private exponent around 1/4 size of modulus - impossible to guess. The reduction of 75% should save a lot of computing effort while still being safe. Shouldn't it?_

## Mission
_Your SIGINT team captured some communication containing key exchange and encrypted data. Can you recover the original message?_

[Download](exchange.pcap)

## Hints
- _Don't waste time with the attempt to brute-force the private key_

---

Open the file in Wireshark. At first, I couldn't find the key exchange, but running
`strings` on the PCAP file helped:
```
$ strings -n 14 exchange.pcap
:1ZLxekTDeSVD+p
{"pubkey": {"n": "dbn25TSjDhUge4L68AYooIqwo0HC2mIYxK/ICnc+8/0fZi1CHo/QwiPCcHM94jYdfj3PIQFTri9j/za3oO+3gVK39bj2O9OekGPG2M1GtN0Sp+ltellLl1oV+TBpgGyDt8vcCAR1B6shOJbjPAFqL8iTaW1C4KyGDVQhQrfkXtAdYv3ZaHcV8tC4ztgA4euP9o1q+kZux0fTv31kJSE7K1iJDpGfy1HiJ5gOX5T9fEyzSR0kA3sk3a35qTuUU1OWkH5MqysLVKZXiGcStNErlaggvJb6oKkx1dr9nYbqFxaQHev0EFX4EVfPqQzEzesa9ZAZTtxbwgcV9ZmTp25MZg==", "e": "S/0OzzzDRdsps+I85tNi4d1i3d0Eu8pimcP5SBaqTeBzcADturDYHk1QuoqdTtwX9XY1Wii6AnySpEQ9eUEETYQkTRpq9rBggIkmuFnLygujFT+SI3Z+HLDfMWlBxaPW3Exo5Yqqrzdx4Zze1dqFNC5jJRVEJByd7c6+wqiTnS4dR77mnFaPHt/9IuMhigVisptxPLJ+g9QX4ZJX8ucU6GPSVzzTmwlDIjaenh7L0bC1Uq/euTDUJjzNWnMpHLHnSz2vgxLg4Ztwi91dOpO7KjvdZQ7++nlHRE6zlMHTsnPFSwLwG1ZxnGVdFnuMjEbPA3dcTe54LxOSb2cvZKDZqA==", "format": ["mpz_export",-1,4,1,0]}, "sessionId":"RmERqOnbsA/oua67sID4Eg=="}
{"sessionId": "RmERqOnbsA/oua67sID4Eg==", "blockId": 0, "data": "fJdSIoC9qz27pWVpkXTIdJPuR9Fidfkq1IJPRQdnTM2XmhrcZToycoEoqJy91BxikRXQtioFKbS7Eun7oVS0yw==", "format": "plain"}
{"sessionId": "RmERqOnbsA/oua67sID4Eg==", "blockId": 0, "msg": "ack"}
{"sessionId": "RmERqOnbsA/oua67sID4Eg==", "blockId": 2, "data": "fRYUyYEINA5i/hCsEtKkaCn2HsCp98+ksi/8lw1HNTP+KFyjwh2gZH+nkzLwI+fdJFbCN5iwFFXo+OzgcEMFqw==", "format": "plain"}
{"sessionId": "RmERqOnbsA/oua67sID4Eg==", "blockId": 2, "msg": "ack"}
{"sessionId": "RmERqOnbsA/oua67sID4Eg==", "blockId": 3, "data": "+y2fMsE0u2F6bp2VP27EaLN68uj2CXm9J1WVFyLgqeQryh5jMyryLwuJNo/pz4tXzRqV4a8gM0JGdjvF84mf+w==", "format": "plain"}
{"sessionId": "RmERqOnbsA/oua67sID4Eg==", "blockId": 3, "msg": "ack"}
{"sessionId": "RmERqOnbsA/oua67sID4Eg==", "blockId": 1, "data": "vzwheJ3akhr1LJTFzmFxdhBgViykRpUldFyU6qTu5cjxd1fOM3xkn49GYEM+2cUVk22Tu5IsYDbzJ4/zSDfzKA==", "format": "plain"}
{"sessionId": "RmERqOnbsA/oua67sID4Eg==", "blockId": 1, "msg": "ack"}
{"sessionID": "RmERqOnbsA/oua67sID4Eg==", "msg": "decrypt"}
{"sessionID": "RmERqOnbsA/oua67sID4Eg==", "msg": "kthxbye"}
2,HS7xu(Ue2hY{z>
```

Alternatively, follow the conversation between `7.7.11.1` and `7.7.11.129` (filter `ip.addr==7.7.11.1`).

In a bit more readable form:
```
{
  "msg": ""
}{
  "pubkey": {
    "n": "dbn25TSjDhUge4L68AYooIqwo0HC2mIYxK/ICnc+8/0fZi1CHo/QwiPCcHM94jYdfj3PIQFTri9j/za3oO+3gVK39bj2O9OekGPG2M1GtN0Sp+ltellLl1oV+TBpgGyDt8vcCAR1B6shOJbjPAFqL8iTaW1C4KyGDVQhQrfkXtAdYv3ZaHcV8tC4ztgA4euP9o1q+kZux0fTv31kJSE7K1iJDpGfy1HiJ5gOX5T9fEyzSR0kA3sk3a35qTuUU1OWkH5MqysLVKZXiGcStNErlaggvJb6oKkx1dr9nYbqFxaQHev0EFX4EVfPqQzEzesa9ZAZTtxbwgcV9ZmTp25MZg==",
    "e": "S/0OzzzDRdsps+I85tNi4d1i3d0Eu8pimcP5SBaqTeBzcADturDYHk1QuoqdTtwX9XY1Wii6AnySpEQ9eUEETYQkTRpq9rBggIkmuFnLygujFT+SI3Z+HLDfMWlBxaPW3Exo5Yqqrzdx4Zze1dqFNC5jJRVEJByd7c6+wqiTnS4dR77mnFaPHt/9IuMhigVisptxPLJ+g9QX4ZJX8ucU6GPSVzzTmwlDIjaenh7L0bC1Uq/euTDUJjzNWnMpHLHnSz2vgxLg4Ztwi91dOpO7KjvdZQ7++nlHRE6zlMHTsnPFSwLwG1ZxnGVdFnuMjEbPA3dcTe54LxOSb2cvZKDZqA==",
    "format": ["mpz_export", -1, 4, 1, 0]
  },
  "sessionId": "RmERqOnbsA/oua67sID4Eg=="
}{
  "sessionId": "RmERqOnbsA/oua67sID4Eg==",
  "blockId": 0,
  "data": "fJdSIoC9qz27pWVpkXTIdJPuR9Fidfkq1IJPRQdnTM2XmhrcZToycoEoqJy91BxikRXQtioFKbS7Eun7oVS0yw==",
  "format": "plain"
}{
  "sessionId": "RmERqOnbsA/oua67sID4Eg==",
  "blockId": 0,
  "msg": "ack"
}{
  "sessionId": "RmERqOnbsA/oua67sID4Eg==",
  "blockId": 2,
  "data": "fRYUyYEINA5i/hCsEtKkaCn2HsCp98+ksi/8lw1HNTP+KFyjwh2gZH+nkzLwI+fdJFbCN5iwFFXo+OzgcEMFqw==",
  "format": "plain"
}{
  "sessionId": "RmERqOnbsA/oua67sID4Eg==",
  "blockId": 2,
  "msg": "ack"
}{
  "sessionId": "RmERqOnbsA/oua67sID4Eg==",
  "blockId": 3,
  "data": "+y2fMsE0u2F6bp2VP27EaLN68uj2CXm9J1WVFyLgqeQryh5jMyryLwuJNo/pz4tXzRqV4a8gM0JGdjvF84mf+w==",
  "format": "plain"
}{
  "sessionId": "RmERqOnbsA/oua67sID4Eg==",
  "blockId": 3,
  "msg": "ack"
}{
  "sessionId": "RmERqOnbsA/oua67sID4Eg==",
  "blockId": 1,
  "data": "vzwheJ3akhr1LJTFzmFxdhBgViykRpUldFyU6qTu5cjxd1fOM3xkn49GYEM+2cUVk22Tu5IsYDbzJ4/zSDfzKA==",
  "format": "plain"
}{
  "sessionId": "RmERqOnbsA/oua67sID4Eg==",
  "blockId": 1,
  "msg": "ack"
}{
  "sessionID": "RmERqOnbsA/oua67sID4Eg==",
  "msg": "decrypt"
}  {
  "sessionID": "RmERqOnbsA/oua67sID4Eg==",
  "msg": "kthxbye"
}          
```

BLOCK IDs are swapped!!!

 

https://www.slideshare.net/dganesan11/analysis-of-short-rsa-private-exponent-d-133076428
