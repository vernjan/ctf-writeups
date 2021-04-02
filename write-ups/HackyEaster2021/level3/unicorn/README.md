# Unicorn
🦄 Ain't no CTF without a unicorn! 🦄

```
s7GvyM1RKEstKs7Mz7NVMtQzUFJIzUvO  
T8nMS7dVCg1x07VQsrfj5bJJzs9LL0os  
KQayFRRs0nIS0+0yUo0MjAyrS/MMkw2K  
8uIN84CiJcbGximKtTb6YBVAffpwjQA=  
```

---

I will repeat myself, not taking the available hint was a **big mistake**. I wasted time on this one as well.

Again, I ran into a rabbit hole. I thought _unicorn_ is a hint for _unicode_ and I tried
to decode the message using various encodings.

After taking the hint: `Decode and inflate!` I, again, easily googled the correct solution 
https://www.samltool.com/decode.php.
> Use this tool to base64 decode and inflate an intercepted SAML Message.

Message decodes to:
```
<?xml version="1.0" encoding="UTF-8"?>
<congrats>
  <flag>he2021{un1c0rn_1nflat333d!}</flag>
</congrats>
```

The flag is `he2021{un1c0rn_1nflat333d!}`