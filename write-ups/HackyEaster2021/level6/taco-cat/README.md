# Taco Cat
Was it a cat I saw?

[tacocat.zip](tacocat.zip)

---

The archive is, of course, password protected.

We can at least list the archived files:
```
$ unzip -l tacocat.zip
Archive:  tacocat.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
    20477  05-19-2020 16:51   eggge.png
---------                     -------
    20477                     1 file
```

Hmm, `eggge.png` and `tacocat.zip`. Both file names are [palindromes](https://en.wikipedia.org/wiki/Palindrome)!

The best guess is the **password is also a palindrome**.

I spent some time figuring out how to produce palindromes using [John the Ripper](https://www.openwall.com/john/).

I didn't find any easy way. You can't combine _incremental_ attack with rules :-(.

Luckily, you can read passwords from _stdin_.
Here is a simple script to produce palindromes (lowercase, palindrome length is 9):
```python
from itertools import product
import string

passwords = product(string.ascii_lowercase, repeat=5)

for password in passwords:
    password = ''.join(password)
    print(password + password[1::-1])

```

Hook it up with John:
```
$ zip2john tacocat.zip > tacocat.hash
$ python3 palindrome.py | john --pipe tacocat.hash
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press Ctrl-C to abort, or send SIGUSR1 to john process for status
mousesuom        (tacocat.zip/eggge.png)
1g 0:00:00:18  0.05414g/s 622272p/s 622272c/s 622272C/s ('m', 'o', 's', 'y', 'y')..mozalazom
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Cool, the password is `mousesuom`.

Unzip the archive and get the egg:

![](eggge.png)

The flag is `he2021{!y0.ban4na.b0y!}`