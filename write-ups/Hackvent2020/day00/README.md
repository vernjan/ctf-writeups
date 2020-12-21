# HV20.(-1) Twelve steps of christmas

_On the third day of christmas my true love sent to me..._

_three caesar salads,_  
_two to (the) six arguments,_  
_one quick response._

[message](message)

---

The first part of the message is:
```
Sbopb 3 alkb! Lcc tfqe vlr! Dbq yxzh ql tloh! Vlr'ob klq alkb ebob...
```

Let's try [Caesar cihper](https://www.dcode.fr/caesar-cipher):
```
Verse 3 done! Off with you! Get back to work! You're not done here...
```

Apply the same ROT+23 to the second part of the message (the **Q**uick **R**esponse).
See [qr-decrypted](qr-decrypted).

Decode from base64:
```
$ cat qr-decrypted | base64 -d > qr.png
```

![](qr.png)

Finally, enhance the black color:

![](qr-black.jpg)

The first flag is `HV20{34t-sl33p-haxx-rep34t}`

---

💡 Fun fact, the original verse 3 is:
```
On the third day of Christmas my true love sent to me
Three french hens
Two turtle doves, and
A partridge in a pear tree
``` 
