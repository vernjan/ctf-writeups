# Finding Mnemo
Dorie has forgotten everything again... Luckily, there is a backup:

```
adapt    3555  
bind     824e  
bless    8fcf  
blind    81db  
civil    03ec  
craft    ed05  
garage   9db4  
good     d2ba  
half     1272   
hip      8d53  
home     21b7  
hotel    1cb0  
lonely   e5b8  
magnet   16b9  
metal    770e  
mushroom dd80  
napkin   0829  
reason   ecd3  
rescue   5ef2  
ring     e3b0  
shift    4ea1  
small    f1f6  
sunset   b271  
tongue   f08d  
```

---

Googling the random looking words, I discovered [BIP 0039](https://en.bitcoin.it/wiki/BIP_0039).

I had to do a bit of reading:
- https://en.bitcoin.it/wiki/Seed_phrase 
- https://medium.com/mycrypto/the-journey-from-mnemonic-phrase-to-address-6c5e86e11e14  
- https://bitcoinbriefly.com/ultimate-guide-to-bitcoin-wallets-seeds-private-keys-public-keys-and-addresses/

I was thinking where the flag could be hidden, and my best guess was in the _original entropy_.

However, the first step is to find a way how to sort the seed phrase. The current state is not even valid:

```python
from mnemonic import Mnemonic

mnemo = Mnemonic("english")

words = ["adapt", "bind", "bless", "blind", "civil", "craft", "garage", "good", "half", "hip", "home", "hotel",
          "lonely", "magnet", "metal", "mushroom", "napkin", "reason", "rescue", "ring", "shift", "small", "sunset",
          "tongue"]

entropy = mnemo.to_entropy(words)
print(entropy)
```

It outputs: `ValueError: Failed checksum.`

Next, I tried reverse engineering to confirm the previous idea.
My thinking was if the flag starts with `he2021{` (7 * 8 bytes = 56 bits), then I should be able to recover the first
5 words in correct order (5 * 11 bits).
I replaced the entropy value (in a debugger) with a dummy flag `he2021{aaaaaaaaaaaaaaaaaaaaaaaa}`:

![](mnemo-entropy.png)

This is looking good! The first 5 words are indeed present on Dorie's list:
```
half    1272
civil   03ec
metal   770e
good    d2ba
bless   8fcf
```
