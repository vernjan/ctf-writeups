# Pix FX
Hey there! We have our fancy new Pix FX service online!

Try it out!

http://46.101.107.117:2110

---

![](pixfx-main.png)

Submitting the form returns a similar code:
```
28CEA35762D93617580F0C445BEB71D2F1BE27244F934E3314AC0D8BB776FA3BFF88D87D78205839D04F7CE96CCFDBCD54DFFB91E9CD6ADBD3E5AC222D4F710D
```

![](pixfx-code.png)

I noticed two interesting things:
1) the codes for popular FX have different sizes

A few observations:
- the **code is always different**, even for the same combinations of the chosen image and effect
- the **code is always 64 bytes** when submitting the form
- however, it's only 48 bytes for some _popular FX_
- one of _popular FX_ codes is`41E5D00E5CECC3019834C99B403DE4B24933AF3087BCE219699D7E3EB178A06F7B4717A36C617760EC0AD8BFD5DF05B2`
  and it points to the egg:
  ![](choco-egg.png)

There are different error messages based on the input:
- `Decryption Error`
- `Error processing image null`
- `Parse error`