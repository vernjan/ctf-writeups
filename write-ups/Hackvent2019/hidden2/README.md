# HV19.H2 Hidden Two
_Again a hidden flag._

---

_Note: The challenge was released on [Day 7](../day07/README.md)._
 
Now I knew I should focus on [Day 7](../day07/README.md). From the beginning, I didn't like
the name of the video. `3DULK2N7DcpXFg8qGo9Z9qEQqvaEDpUCBB1v.mp4` is too complicated..

The first thing I tried was decoding using _Base64_:
```
5+c{
W*Yo
```

Hm, does not look that bad.. `{` is correct. Ok, let's try
[Base58](https://www.browserling.com/tools/base58-decode). Yes!

The flag is `HV19{Dont_confuse_0_and_O}` 