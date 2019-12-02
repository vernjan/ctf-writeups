# HV19.03 Hodor, Hodor, Hodor

![](hodor.jpg)

```
$HODOR: hhodor. Hodor. Hodor!?  = `hodor?!? HODOR!? hodor? Hodor oHodor. hodor? , HODOR!?! ohodor!?  dhodor? hodor odhodor? d HodorHodor  Hodor!? HODOR HODOR? hodor! hodor!? HODOR hodor! hodor? ! 

hodor?!? Hodor  Hodor Hodor? Hodor  HODOR  rhodor? HODOR Hodor!?  h4Hodor?!? Hodor?!? 0r hhodor?  Hodor!? oHodor?! hodor? Hodor  Hodor! HODOR Hodor hodor? 64 HODOR Hodor  HODOR!? hodor? Hodor!? Hodor!? .

HODOR?!? hodor- hodorHoOodoOor Hodor?!? OHoOodoOorHooodorrHODOR hodor. oHODOR... Dhodor- hodor?! HooodorrHODOR HoOodoOorHooodorrHODOR RoHODOR... HODOR!?! 1hodor?! HODOR... DHODOR- HODOR!?! HooodorrHODOR Hodor- HODORHoOodoOor HODOR!?! HODOR... DHODORHoOodoOor hodor. Hodor! HoOodoOorHodor HODORHoOodoOor 0Hooodorrhodor HoOodoOorHooodorrHODOR 0=`;
hodor.hod(hhodor. Hodor. Hodor!? );
```

---

At first I thought this is a known obfuscated programming language but as it turns out - it is not.
I googled for `programming language question and exclamation mark` which pointed me to [Ook!](https://cs.wikipedia.org/wiki/Ook!).
No exactly the same but close.. Then I had the idea to simply google for `programming language hodor` and bingo - 
http://www.hodor-lang.org/.

I installed the NPM package (`npm install -g hodor-lang`) and executed the given code
(apparently, it's important to add `.hd` file extension).
```
$ hodor day03.hd
HODOR: \-> day03.hd
Awesome, you decoded Hodors language! 

As sis a real h4xx0r he loves base64 as well.

SFYxOXtoMDFkLXRoMy1kMDByLTQyMDQtbGQ0WX0=

$ echo SFYxOXtoMDFkLXRoMy1kMDByLTQyMDQtbGQ0WX0= | base64 -d
HV19{h01d-th3-d00r-4204-ld4Y}
```

The flag is `HV19{h01d-th3-d00r-4204-ld4Y}`