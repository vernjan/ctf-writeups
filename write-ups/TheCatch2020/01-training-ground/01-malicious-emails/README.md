# Malicious e-mails

Hi, junior investigator!

We have extracted a bunch of suspicious e-mails. We believe that you can analyze them and find their secret.

Use password `MaIlZZzz-20` to [download the evidence](malicious_emails.zip)

Good Luck!

---

Download and unzip the evidence:

```
$ ls
093c5905abeee42eff54db6f97b85c25.eml
19cb66edcd40d78abe611187c4dced5c.eml
26ba12de3d6a928ff46cdf2a49131b4e.eml
3fc4a05ab593fcdb6e0d4200a65530d2.eml
42b8512a8eab9b2121af897ff0d21136.eml
44dc58f1ee71cdfe7d104f257aaa9261.eml
47568fc46b0fbcd3af2b566e0240bfc8.eml
4b8dc0add62ef7df265dbf3253a85fd8.eml
536bc56a7d01210beb4bc8a7c5ef6065.eml
71ad11612c9ae0c57e1eedd96f2024b7.eml
71f92e9b17158f245086995aa4bf4c2b.eml
740f4aa25299a922884a3dcb14321fcf.eml
7b7e5fe3e930615da6a1227cbf3c4447.eml
7e5be3fbaa32cc9c7b384af0cc10f096.eml
7f097fa042da86d731beb1c032f4a98d.eml
8528d2f7f5f70c42d0f9bf1650cb406a.eml
8afb86ac4470096daa2cd54db1a65ec6.eml
9e171401469c8669c847a12d3bc26efb.eml
9f95ef3c78c5b1c2d9331eef2580f7fa.eml
a5289050b9405903e2b9a4b92b9a9bdf.eml
ac54290efa9631d78060d2aa375caaf6.eml
aca5b849d1aa5ff44dc74a1eb6d96304.eml
afabf938e104f008aee040ada3833678.eml
b5c061e5d3c788ccf81472a3e87d1847.eml
b6d75e5c511d24e34382f99e142e0134.eml
b99b01d75c7369c335dc7c992fa3eabd.eml
c19f9913a01b670021458f5c628342ab.eml
cff9cb2abe4dc10ecd675f87f271a200.eml
db43e0d64ec40785d8b119445d2f06d4.eml
e7e8469f4413951740ec77f2b6e3581d.eml
e875cdc29d84f415987fcc255333f095.eml
e945034c1dc01f7c3cc2097d1e9c25c9.eml
emls.md5
```

There is a bunch of [.eml files](https://fileinfo.com/extension/eml).
You can open them easily with _Microsoft Outlook_ or _Mozilla Thunderbird_.

I rejected to automate this task since there is not so many of them. Simply reading through them one by one
got me to `47568fc46b0fbcd3af2b566e0240bfc8.eml`:

> Somebody want to share his wealth with you - check the offer at http://challenges.thecatch.cz:20100/npelfsd0btmaovy2 and profit!

Follow the link and grab the flag: `FLAG{Tyqz-EgrI-8G7E-6PKB}`
