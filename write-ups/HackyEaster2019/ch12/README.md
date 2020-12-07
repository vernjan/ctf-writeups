# 12 - Decrypt0r

*Crack the might Decryt0r and make it write a text with a flag.*

*No Easter egg here. Enter the flag directly on the flag page.*

[decryptor.zip](decryptor.zip)

---

I unzipped the archive and started to play with it.

```
$ file decryptor 
decryptor: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=1835d7dad4e2511aef2328a6fc9a2bb17f36f4e6, with debug_info, not stripped
```

We have a `ELF 64-bit LSB executable` binary. Let's run it!

```
$ ./decryptor 
Enter Password: hello
X0r_wu1Pn2lzu+ib2n \m-oh=(vU?<q`Tc?"n{9p	;6y< ...
```

OK, we need the correct password .. Time for reverse engineering.
I used both [Hopper Disassembler](https://www.hopperapp.com/download.html) and [Ghidra](https://ghidra-sre.org/).

Here is the relevant output from Hopper:

```
int cz.vernjan.ctf.hv20.cz.vernjan.ctf.hv20.cz.vernjan.ctf.hv20.main(int arg0, int arg1) {
    printf("Enter Password: ");
    fgets(&var_10, 0x10, *__TMC_END__); // Read the password from CLI
    rax = hash(&var_10); // Do some magic
    printf(rax); // Print result
    return 0x0;
}
```

We get the big picture here: read the password (max 15 characters!), do some magic, print the result ..


Here comes the magic:
```
int _Z4hashPj(unsigned int * arg0) {
    var_10 = malloc(0x34d);
    var_14 = strlen(arg0) - 0x1;
    var_20 = var_10;
    var_28 = arg0;
    var_4 = 0x0;
    while (sign_extend_32(var_4) <= 0xd2) {
            for (var_8 = 0x0; var_8 <= 0x3; var_8 = var_8 + 0x1) {
                    *(int8_t *)(var_20 + sign_extend_64(var_8 + var_4 * 0x4)) = *(int8_t *)(var_28 + (var_8 + var_4 * 0x4) % var_14) & 0xff;
            }
            *(int32_t *)(var_10 + sign_extend_32(var_4) * 0x4) = (0xc090603 << 0x1) + (0xffffffffcfdbe7f3 + (0xc090603 << 0x1) - ((0xffffffff98badcfe - (*(int32_t *)(var_10 + sign_extend_32(var_4) * 0x4) & 0xffffffffffffffff - (*(int32_t *)(0x601060 + sign_extend_32(var_4) * 0x4) & *(int32_t *)(var_10 + sign_extend_32(var_4) * 0x4)))) + 0x67452301 & 0xffffffffffffffff - (*(int32_t *)(0x601060 + sign_extend_32(var_4) * 0x4) & (0xffffffffefcdab89 - (*(int32_t *)(0x601060 + sign_extend_32(var_4) * 0x4) & *(int32_t *)(var_10 + sign_extend_32(var_4) * 0x4))) + 0x10325476)));
            var_4 = var_4 + 0x1;
    }
    rax = var_10;
    return rax;
}
```

This is, of course, quite unreadable. I rewrite it a bit to understand what's going on:

```
int _Z4hashPj(unsigned int * arg0) {
    result = malloc(0x34d); // allocate 845 bytes (the printed result)
    passwLen = strlen(arg0) - 1;
    passw = arg0; // pointer to passw
    
    i = 0;
    while (i <= 210) { 
    
      // password is rotated in 4 bytes chunks !!!
      for (j = 0; j <= 3; j++) {
        *(int8_t *)(result + sign_extend_64(j + i * 0x4)) = *(int8_t *)(passw + (j + i * 0x4) % passwLen) & 0xff;
      }
      
      // do more magic
      ...
      
      i++;
    }
    
    return result;
}
```

The important thing here is that the decryption algorithm uses **just one integer (4 bytes) at a time**! We can try to
brute force the password piece by piece. It's just 4 printable characters! Of course, we will need
to somehow guess the expected output ..

I rewrote the *do more magic* part to Kotlin. This is pretty much it:
```kotlin
fun decrypt(password: UInt, data: UInt): UInt =
        password - (data and password) + (data and (0xffffffffu - (data and password)))
```

To be able to decrypt piece by piece, first we need to know the password length. Once we have it,
we know which integers where encrypted with the same partial password.
 
I did a small analysis to help me guess the password length. Testing all the possible password
lengths with all possible partial passwords (i.e. 4 characters) and looking for numbers of possible
ASCII printable outputs. This is the result:

```
{
    4={0=0},
    5={0=0, 1=0, 2=0, 3=0, 4=0},
    6={0=0, 1=8694, 2=0},
    7={0=0, 1=0, 2=0, 3=0, 4=0, 5=0, 6=0},
    8={0=0, 1=0},
    9={0=0, 1=0, 2=0, 3=0, 4=0, 5=0, 6=0, 7=10143, 8=0},
    10={0=0, 1=0, 2=0, 3=202860, 4=0},
    11={0=0, 1=0, 2=0, 3=0, 4=0, 5=0, 6=0, 7=11000, 8=0, 9=650, 10=0},
    12={0=0, 1=0, 2=0},
    13={0=654368, 1=29744, 2=331200, 3=255552, 4=1104840, 5=377177, 6=328900, 7=303600, 8=1267760, 9=115275, 10=750000, 11=409200, 12=859375},
    14={0=0, 1=48, 2=1352, 3=0, 4=0, 5=0, 6=1196},
    15={0=0, 1=0, 2=0, 3=360000, 4=0, 5=0, 6=14352, 7=18816, 8=390000, 9=0, 10=0, 11=38400, 12=0, 13=0, 14=1196}
}
```

Apparently, the password is 13 characters long!

Another fact is that the password is rotated `mod 4`:
```
1    2    3    4    5    6    7    8    9    10   11   12   13
1234 5678 9abc d123 4567 89ab cd12 3456 789a bcd1 2345 6789 abcd
```

No we need to guess the output. I assumed that the text could start (the first 4 bytes) with a capital letter and contain letters only..
To my surprise, I really found a string `Hell` as one of the possible results. Also, other parts of this first
data set were looking good. See below.

**Step 1**: Password characters `1,2,3 and 4` (set 1):
```
x0r_: Hell s-yu ommo elf, pher s. I ther ://e ircu th N " an ithe D ga n XN y in th a ki/X
```

The cool thing is that partial passwords overlap (`13 mod 4`). So the 4th dataset uses the same password with just 1 different
letter.

**Step 2**: Password characters `d,1,2,3` (set 4):
```
dx0r: rats bN8U ompo  con vial nten wn t dia. e ma NOR  gica ogic repl  whi the  OR g 
```

**Step 3**: Password characters `c,d,1,2` (set 7):
```
ndx0: nd t  XOR more peat oken  mes key  /XOR four e so on c logi NOR  e co r on (htt 
```

And so on .. The more letters I was able to guess (one by one) the easier it was. 

The final password is: `x0r_w1th_n4nd`

```
$ ./decryptor

Enter Password: x0r_w1th_n4nd
Hello, 
congrats you found the hidden flag: he19-Ehvs-yuyJ-3dyS-bN8U. 

'The XOR operator is extremely common as a component in more complex ciphers. By itself, using a constant repeating key, a simple XOR cipher can trivially be broken using frequency analysis. If the content of any message can be guessed or otherwise known then the key can be revealed.'
(https://en.wikipedia.org/wiki/XOR_cipher)

'An XOR gate circuit can be made from four NAND gates. In fact, both NAND and NOR gates are so-called "universal gates" and any logical function can be constructed from either NAND logic or NOR logic alone. If the four NAND gates are replaced by NOR gates, this results in an XNOR gate, which can be converted to an XOR gate by inverting the output or one of the inputs (e.g. with a fifth NOR gate).' 
(https://en.wikipedia.org/wiki/XOR_gate)
```

Face palm, the frequency analysis would really have been easier .. Nevermind!

*Note*: I decided not to include my code snippets here because they were a total mess :)