# HV19.H4 Hidden Four

_No description_

---

_Note: The challenge was released on [Day 14](../day14/README.md).

The solution is quite simple. The weird looking flag from [Day 14](../day14/README.md)
is a **Perl expression**.

```perl5
$hidden_flag = s@@jSfx4gPcvtiwxPCagrtQ@,y^p-za-oPQ^a-z\x20\n^&&s[(.)(..)][\2\1]g;s%4(...)%"p$1t"%ee;
print $hidden_flag;
```

The flag is `HV19{Squ4ring the Circle}`

_Similar expressions were present in the original obfuscated code
so if you did a good job understanding the code then it was quite obvious._