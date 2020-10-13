# Wiretaped message

Hi, junior investigator!

We have wiretaped strange communication - probably a message. Try to decode it.

Use password `wiREtaPeD-msG` to [download the evidence](wiretaped_message.zip)

Good Luck!

---

Download and unzip the evidence:

```
$ ls
message
message.md5
```

What file format is the message?

```
$ file message
message: data
```

It's raw `data` so let's use `xxd` to read in hex:

```
$ xxd message
00000000: 0054 5158 4277 5a57 4679 4948 646c 5957  .TQXBwZWFyIHdlYW
00000010: 7367 6432 686c 6269 4235 6233 5567 5958  sgd2hlbiB5b3UgYX
00000020: 4a6c 4948 4e30 636d 3975 5a79 7767 5957  JlIHN0cm9uZywgYW
00000030: 356b 4948 4e30 636d 3975 5a79 4233 6147  5kIHN0cm9uZyB3aG
00000040: 5675 4948 6c76 6453 4268 636d 5567 6432  VuIHlvdSBhcmUgd2
00000050: 5668 6179 343d 0054 5647 686c 4948 4e31  Vhay4=.TVGhlIHN1
00000060: 6348 4a6c 6257 5567 5958 4a30 4947 396d  cHJlbWUgYXJ0IG9m
00000070: 4948 6468 6369 4270 6379 4230 6279 427a  IHdhciBpcyB0byBz
00000080: 6457 4a6b 6457 5567 6447 686c 4947 5675  dWJkdWUgdGhlIGVu
00000090: 5a57 3135 4948 6470 6447 6876 6458 5167  ZW15IHdpdGhvdXQg
000000a0: 5a6d 6c6e 6148 5270 626d 6375 0164 5357  ZmlnaHRpbmcu.dSW
000000b0: 5967 6557 3931 4947 7475 6233 6367 6447  YgeW91IGtub3cgdG
000000c0: 686c 4947 5675 5a57 3135 4947 4675 5a43  hlIGVuZW15IGFuZC
000000d0: 4272 626d 3933 4948 6c76 6458 4a7a 5a57  Brbm93IHlvdXJzZW
000000e0: 786d 4c43 4235 6233 5567 626d 566c 5a43  xmLCB5b3UgbmVlZC
000000f0: 4275 6233 5167 5a6d 5668 6369 4230 6147  Bub3QgZmVhciB0aG
00000100: 5567 636d 567a 6457 7830 4947 396d 4947  UgcmVzdWx0IG9mIG
00000110: 4567 6148 5675 5a48 4a6c 5a43 4269 5958  EgaHVuZHJlZCBiYX
00000120: 5230 6247 567a 4c69 424a 5a69 4235 6233  R0bGVzLiBJZiB5b3
00000130: 5567 6132 3576 6479 4235 6233 5679 6332  Uga25vdyB5b3Vyc2
00000140: 5673 5a69 4269 6458 5167 626d 3930 4948  VsZiBidXQgbm90IH
00000150: 526f 5a53 426c 626d 5674 6553 7767 5a6d  RoZSBlbmVteSwgZm
00000160: 3979 4947 5632 5a58 4a35 4948 5a70 5933  9yIGV2ZXJ5IHZpY3
00000170: 5276 636e 6b67 5a32 4670 626d 566b 4948  RvcnkgZ2FpbmVkIH
00000180: 6c76 6453 4233 6157 7873 4947 4673 6332  lvdSB3aWxsIGFsc2
00000190: 3867 6333 566d 5a6d 5679 4947 4567 5a47  8gc3VmZmVyIGEgZG
000001a0: 566d 5a57 4630 4c69 424a 5a69 4235 6233  VmZWF0LiBJZiB5b3
000001b0: 5567 6132 3576 6479 4275 5a57 6c30 6147  Uga25vdyBuZWl0aG
000001c0: 5679 4948 526f 5a53 426c 626d 5674 6553  VyIHRoZSBlbmVteS
000001d0: 4275 6233 4967 6557 3931 636e 4e6c 6247  Bub3IgeW91cnNlbG
000001e0: 5973 4948 6c76 6453 4233 6157 7873 4948  YsIHlvdSB3aWxsIH
000001f0: 4e31 5932 4e31 6257 4967 6157 3467 5a58  N1Y2N1bWIgaW4gZX
00000200: 5a6c 636e 6b67 596d 4630 6447 786c 4c67  ZlcnkgYmF0dGxlLg
00000210: 3d3d 007c 5447 5630 4948 6c76 6458 4967  ==.|TGV0IHlvdXIg
00000220: 6347 7868 626e 4d67 596d 5567 5a47 4679  cGxhbnMgYmUgZGFy
00000230: 6179 4268 626d 5167 6157 3177 5a57 356c  ayBhbmQgaW1wZW5l
00000240: 6448 4a68 596d 786c 4947 467a 4947 3570  dHJhYmxlIGFzIG5p
00000250: 5a32 6830 4c43 4268 626d 5167 6432 686c  Z2h0LCBhbmQgd2hl
00000260: 6269 4235 6233 5567 6257 3932 5a53 7767  biB5b3UgbW92ZSwg
00000270: 5a6d 4673 6243 4273 6157 746c 4947 4567  ZmFsbCBsaWtlIGEg
00000280: 6447 6831 626d 526c 636d 4a76 6248 5175  dGh1bmRlcmJvbHQu
00000290: 006c 5533 5677 636d 5674 5a53 426c 6547  .lU3VwcmVtZSBleG
000002a0: 4e6c 6247 786c 626d 4e6c 4947 4e76 626e  NlbGxlbmNlIGNvbn
000002b0: 4e70 6333 527a 4947 396d 4947 4a79 5a57  Npc3RzIG9mIGJyZW
000002c0: 4672 6157 356e 4948 526f 5a53 426c 626d  FraW5nIHRoZSBlbm
000002d0: 5674 6553 647a 4948 4a6c 6332 6c7a 6447  VteSdzIHJlc2lzdG
000002e0: 4675 5932 5567 6432 6c30 6147 3931 6443  FuY2Ugd2l0aG91dC
000002f0: 426d 6157 646f 6447 6c75 5a79 343d 0158  BmaWdodGluZy4=
...
```

There is an obvious pattern: A list of `Base64` encoded messages separated with __2 bytes__.
The first byte is always one of `00`, `01` or `02` and the second byte appears to be kind of random.

I split the message by those 2 bytes and decoded with `Base64`
(see [WiretapedMessages.kt](../../../../src/main/kotlin/cz/vernjan/ctf/catch20/WiretapedMessages.kt)):

```
Appear weak when you are strong, and strong when you are weak.
The supreme art of war is to subdue the enemy without fighting.
If you know the enemy and know yourself, you need not fear the result of a hundred battles. If you know yourself but not the enemy, for every victory gained you will also suffer a defeat. If you know neither the enemy nor yourself, you will succumb in every battle.
Let your plans be dark and impenetrable as night, and when you move, fall like a thunderbolt.
Supreme excellence consists of breaking the enemy's resistance without fighting.
All warfare is based on deception. Hence, when we are able to attack, we must seem unable; when using our forces, we must appear inactive; when we are near, we must make the enemy believe we are far away; when far away, we must make him believe we are near.
Victorious warriors win first and then go to war, while defeated warriors go to war first and then seek to win
In the midst of chaos, there is also opportunity
If your enemy is secure at all points, be prepared for him. If he is in superior strength, evade him. If your opponent is temperamental, seek to irritate him. Pretend to be weak, that he may grow arrogant. If he is taking his ease, give him no rest. If his forces are united, separate them. If sovereign and subject are in accord, put division between them. Attack him where he is unprepared, appear where you are not expected .
The greatest victory is that which requires no battle.
To know your Enemy, you must become your Enemy.
Engage people with what they expect; it is what they are able to discern and confirms their projections. It settles them into predictable patterns of response, occupying their minds while you wait for the extraordinary moment — that which they cannot anticipate.
There is no instance of a nation benefitting from prolonged warfare.
Thus we may know that there are five essentials for victory: 1 He will win who knows when to fight and when not to fight. 2 He will win who knows how to handle both superior and inferior forces. 3 He will win whose army is animated by the same spirit throughout all its ranks. 4 He will win who, prepared himself, waits to take the enemy unprepared. 5 He will win who has military capacity and is not interfered with by the sovereign.
Treat your men as you would your own beloved sons. And they will follow you into the deepest valley.
Even the finest sword plunged into salt water will eventually rust.
Move swift as the Wind and closely-formed as the Wood. Attack like the Fire and be still as the Mountain.
When you surround an army, leave an outlet free. Do not press a desperate foe too hard.
Opportunities multiply as they are seized.
The art of war is of vital importance to the State. It is a matter of life and death, a road either to safety or to ruin. Hence it is a subject of inquiry which can on no account be neglected.
There are not more than five musical notes, yet the combinations of these five give rise to more melodies than can ever be heard. There are not more than five primary colours, yet in combination they produce more hues than can ever been seen. There are not more than five cardinal tastes, yet combinations of them yield more flavours than can ever be tasted.
When the enemy is relaxed, make them toil. When full, starve them. When settled, make them move.
Many officers and few men is weak army and will fail to get the FLAG{YHsB-hr0J-W2ol-fV17}
Who wishes to fight must first count the cost
Know yourself and you will win all battles.
If you wait by the river long enough, the bodies of your enemies will float by.
So in war, the way is to avoid what is strong, and strike at what is weak.
To win one hundred victories in one hundred battles is not the acme of skill. To subdue the enemy without fighting is the acme of skill.
Be extremely subtle even to the point of formlessness. Be extremely mysterious even to the point of soundlessness. Thereby you can be the director of the opponent's fate.
When strong, avoid them. If of high morale, depress them. Seem humble to fill them with conceit. If at ease, exhaust them. If united, separate them. Attack their weaknesses. Emerge to their surprise.
```

The flag is `FLAG{YHsB-hr0J-W2ol-fV17}`
