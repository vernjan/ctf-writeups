# HV19.21 Happy Christmas 256

Santa has improved since the last Cryptmas and now he uses harder algorithms to secure the flag.

This is his public key:

```
X: 0xc58966d17da18c7f019c881e187c608fcb5010ef36fba4a199e7b382a088072f
Y: 0xd91b949eaf992c464d3e0d09c45b173b121d53097a9d47c25220c0b4beb943c
```

To make sure this is safe, he used the NIST P-256 standard.

But we are lucky and an Elve is our friend. We were able to gather some details from our whistleblower:
- Santa used a password and SHA256 for the private key (d)
- His password was leaked 10 years ago
- The password is length is the square root of 256
- The flag is encrypted with AES256
- The key for AES is derived with `pbkdf2_hmac`, salt: "TwoHundredFiftySix", iterations: `256 * 256 * 256`

Phew - Santa seems to know his business - or can you still recover this flag?

```
Hy97Xwv97vpwGn21finVvZj5pK/BvBjscf6vffm1po0=
```

---

Ok, so the first thing we have to do is to brute-force Santa's password. There is a lot of hints
which should make it quite easy.

I focused on the elliptic curves crypto (NIST P-256). Brute-forcing through `256 * 256 * 256 = 16,777,216`
iterations of `pbkdf2_hmac` is not feasible.

The password has leaked in 2009 and is 16 characters long so using a dictionary attack make the best sense.
There is a nice [list of data breaches](https://en.wikipedia.org/wiki/List_of_data_breaches) on Wiki.
In 2009, (in)famous RockYou! was breached. You can even find the passwords in Kali Linux distros
(`/usr/share/wordlists/rockyou.txt.gz`).

I used Python's [PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/src/public_key/ecc.html) for
this again:
```python
import base64
import hashlib

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC

encrypted_flag = 'Hy97Xwv97vpwGn21finVvZj5pK/BvBjscf6vffm1po0='

# Dictionary with ~14 millions passwords
f = open('d:\\temp\\rockyou.txt', 'r', errors='replace')

password = f.readline()
while password:
    if len(password) != 17:  # +1 for line breaks
        password = f.readline()
        continue

    passwordBytes = bytes(password.rstrip('\n'), 'UTF-8')
    passwordSHA256 = SHA256.new(passwordBytes)
    d = int(passwordSHA256.hexdigest(), 16)

    try:
        # If the private key (d) is not valid for the given public key (x and y) an exception is thrown
        key = ECC.construct(
            curve='P-256',
            d=d,
            point_x=0xc58966d17da18c7f019c881e187c608fcb5010ef36fba4a199e7b382a088072f,
            point_y=0xd91b949eaf992c464d3e0d09c45b173b121d53097a9d47c25220c0b4beb943c
        )
        print('The password is: ' + password)
        
        # Derive AES key from password
        aesKey = hashlib.pbkdf2_hmac('sha256', passwordBytes, b'TwoHundredFiftySix', 256 * 256 * 256)
        print('The AES key is: ' + aesKey.hex())

        cipher = AES.new(aesKey, AES.MODE_ECB)
        flag = cipher.decrypt(base64.b64decode(encrypted_flag))
        print('The flag is: ' + flag.decode("UTF-8"))

        break
    except ValueError:
        password = f.readline()

```

After a short while, the script outputs the flag:  
```
> The password is: santacomesatxmas

> The AES key is: eb1e0442ca6566e5d687740d246caea6db3b2851f774140d153c848d59515705
> The flag is: HV19{sry_n0_crypt0mat_th1s_year}
```

The flag is `HV19{sry_n0_crypt0mat_th1s_year}`