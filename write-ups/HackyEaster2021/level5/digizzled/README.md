# Digizzled
Had a flag, but it got digizzled. Can you recover it?

```
-------------------------------------  
      o                  o             
      | o      o         |             
    o-O   o--o   o-o o-o | o-o o-o     
|  | | |  | |  /   /  | |-' |       
o-o | o--O | o-o o-o o o-o o       
|                         
o--o
-------------------------------------  
enter flag: [REDACTED]    
digizzling...  
c5ab05ca73f205ca  
```

[digizzle](digizzle)

---

This is [Python bytecode](https://docs.python.org/3/library/dis.html). It's quite well human-readable.
I learned some basics in https://medium.com/@KonfHub/getting-started-with-disassembling-python-code-bcb5c120484d
and then I start producing the original code, checking each step with `dis.dis(the_method)`.

This is my solution:
```python
from itertools import product

p = product("dlsz134", repeat=9)

for i in list(p):
    flag = ''.join(i)

    s = "he2021{%s}" % flag

    def hizzle(s):
        s1 = 13
        s2 = 37
        for n in range(len(s)):
            s1 = (s1 + ord(s[n])) % 65521
            s2 = (s1 * s2) % 65521
        return (s2 << 16) | s1


    def smizzle(a, b):
        return format(a, 'x') + format(b, 'x')


    a = hizzle(s)
    b = hizzle(s[slice(None, None, -1)])
    r = smizzle(a, b)

    if r == "c5ab05ca73f205ca":
        print(s)
        exit(0)


```

The flag is `he2021{d1s4zzl3d}`
