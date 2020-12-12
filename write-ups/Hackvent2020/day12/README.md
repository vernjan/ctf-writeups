# HV20.12 Wiener waltz

## Introduction
_During their yearly season opening party our super-smart elves developed an improved usage of the well known RSA crypto algorithm. Under the "Green IT" initiative they decided to save computing horsepower (or rather reindeer power?) on their side. To achieve this they chose a pretty large private exponent around 1/4 size of modulus - impossible to guess. The reduction of 75% should save a lot of computing effort while still being safe. Shouldn't it?_

## Mission
_Your SIGINT team captured some communication containing key exchange and encrypted data. Can you recover the original message?_

[Download](exchange.pcap)

## Hints
- _Don't waste time with the attempt to brute-force the private key_

---

Open the file in [Wireshark](https://www.wireshark.org/). At first, I couldn't find the key exchange, but running
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

At this point, I made a mistake. The modulus (and public exponent) conversion from Bas64 into an integer is not so easy.
My naive attempt, to convert into a byte array and then into a big integer, was wrong. Notice that the format is:
`"format": ["mpz_export",-1,4,1,0]`. You need to use [mpz_import](https://gmplib.org/manual/Integer-Import-and-Export).

Here is how I did it for the modulus (and the same for the public exponent):
```kotlin
// Convert to byte array (I'm not good in C so I did this in Kotlin):
val nHex = "dbn25TSjDhUge4L...25MZg==".base64ToHex()
println(nHex.chunked(2).map { "0x$it" }.joinToString(","))
// 0x75,0xb9,0xf6,0xe5,0x34,0xa3,0x0e,0x15,0x20,0x7b, ..
```

```c
int main()
{
    mpz_t rop;
    mpz_init(rop);
    char data[256] = {0x75,0xb9,0xf6,0xe5,0x34,0xa3,0x0e,0x15,0x20,0x7b, ...};   
    mpz_import(rop, 64, -1, 4, 1, 0, data);
    gmp_printf("%Zd\n", rop);
}
```

Prints the modulus:
```
21136187113648735910956792902340987261238482724808044660872655926597365083148384784275999147719115005171023510870084682239018605609844594894880405609510814634404536868649155403129057903532257019060842686994634155205978467383309519881921823354273590936861045431841523283059891729069450531823193829758198452195159839001802409808310303539270828581792136817589972743921904535921749280330153901291531642543946250472645757855636930605097838505480384294629089321241798555566459046743741824235125746402090921912493396059817338067723079903962753795145687173236901003277653830701564333638891277876961702941978996729372105897701
```

Use the same approach to get the public exponent:
```
12703148700486856571456640284543930158485441147798980218669328932721873837903118006895885638306703700146300157588744922573525972231890883171794381140159146432366116691422353585619938803060563166160513071142031888780581428871210353376077782114636012547145421154246397069298658668372048637974096728556378192041823865600245728866360820303463508288677034505462614941425772365440025016354622878586568634346248386264921756141627262617888108166058845769396410463089005177762158324354462305559557728141729110983431022424786938837309186823930758907423061347118761390982013522713098779662020937499191572512966979990705904881359
```

The last step was easy with [RsaCtfTool](https://github.com/Ganapati/RsaCtfTool):
```
$ ./RsaCtfTool.py -n 21136.. -e 12703.. --attack wiener --uncipher 0x7c97522280bdab3dbba565699174c87493ee47d16275f92ad4824f4507674ccd979a1adc653a32728128a89cbdd41c629115d0b62a0529b4bb12e9fba154b4cbbf3c21789dda921af52c94c5ce6171761060562ca4469525745c94eaa4eee5c8f17757ce337c649f8f4660433ed9c515936d93bb922c6036f3278ff34837f3287d1614c98108340e62fe10ac12d2a46829f61ec0a9f7cfa4b22ffc970d473533fe285ca3c21da0647fa79332f023e7dd2456c23798b01455e8f8ece0704305abfb2d9f32c134bb617a6e9d953f6ec468b37af2e8f60979bd2755951722e0a9e42bca1e63332af22f0b89368fe9cf8b57cd1a95e1af20334246763bc5f3899ffb
private argument is not set, the private key will not be displayed, even if recovered.

[*] Testing key /tmp/tmpg6td52gy.
[*] Performing wiener attack on /tmp/tmpg6td52gy.

Results for /tmp/tmpg6td52gy:

Unciphered data :
HEX : 0x010000000000000000000000000000000d596f75206d61646520697421204865726520697320796f757220666c61673a20485632307b35686f72375f507269763378705f61316e375f6e305f356d6172377d0d0d476f6f64206c75636b20666f72204861636b76656e742c206d6572727920582d6d617320616e6420616c6c20746865206265737420666f7220323032312c2067726565747a20536d617274536d7572660000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
INT (big endian) : 126238304966058622268417487065116999850437134325536947829809719361127458755172485878921607819562782137130889672682181546083146219920895001981593670137044046743324371083748919195718873813030582560300857962722122711687061722726352957253912732329715168764879103790633790353869417644884138321766902995416951438094706986290503306724832922071317615118702045605936810666030222365158751061015374664438232254524326498415356246494186372113680660460979641507864116161788329759655576030268164715746281165718383959487489864531271131721901386518889031399849955290811846447606970713955684530967847283343558302790225039391161581568
INT (little endian) : 35777833055008548352966557653083382831106599491571495629407517820928032266385997711004153126794065804891450922494698117936869883855336766529359192561422450015937198165927464566798598870158868371697669544978541864981287844793911310621880628884649252256195590915609577650689494262139556459806311936200604020894322427559829422099663854121868157500962317492849406829255954509052732319673190577078273
STR : b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\rYou made it! Here is your flag: HV20{5hor7_Priv3xp_a1n7_n0_5mar7}\r\rGood luck for Hackvent, merry X-mas and all the best for 2021, greetz SmartSmurf\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
```

Value for `--uncipher` is a simple conversion Base64 --> hex.

The flag is `HV20{5hor7_Priv3xp_a1n7_n0_5mar7}`
