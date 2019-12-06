# HV19.05 Santa Parcel Tracking
_To handle the huge load of parcels Santa introduced this year a parcel tracking system.
He didn't like the black and white barcode, so he invented a more solemn barcode.
Unfortunately the common barcode readers can't read it anymore, it only works with the
pimped models santa owns. Can you read the barcode_

![](barcode.png)

---

This one gave me hard times. I took a wrong approach and I was trying to google something that
would read the barcode. It reminded me a challenge from the last year -
[Just Another Bar Code](https://github.com/pavelvodrazka/ctf-writeups/blob/master/hackvent2018/challenges/day01/README.md).
Then I tried to google the `SP-Tracking` number, going through some Parcel tracking systems such as
UPS or DHL. No luck.

Finally, I decided to take the _hands on_ approach and analyse the colors. I wrote my own
[Barcode scanner](../../../src/main/kotlin/cz/vernjan/ctf/hv19/day05/BarcodeScanner.kt)
in Kotlin to extract RGB values. Then it was quite obvious. All R/G/B values were within
printable ASCII ranges. I tried the channels one by one and discovered that _blue_ channel
contains a hidden message: `X8YIOF0ZP4S8HV19{D1fficult_to_g3t_a_SPT_R3ader}S1090OMZE0E3NFP6E`

The flag is `{D1fficult_to_g3t_a_SPT_R3ader}`

P.S. I finished this challenge a few minutes before the midnight - What a great feeling! :-)