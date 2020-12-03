# HV20.03 Packed gifts

_One of the elves has unfortunately added a password to the last presents delivery and we cannot open it. The elf has taken a few days off after all the stress of the last weeks and is not available. Can you open the package for us?_

_We found the following packages:_

[Package 1](package1.zip)  
[Package 2](package2.zip)

---

The first archive contains 100 files:
```
$ unzip -l package1.zip 
Archive:  package1.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
      172  11-24-2020 09:07   0000.bin
      172  11-24-2020 09:07   0001.bin
      172  11-24-2020 09:07   0002.bin
...
      172  11-24-2020 09:07   0099.bin
---------                     -------
    17200                     100 files
```

All the files are pretty much the same. For example `0000.bin`:
```
CNn9RZ6KFvkJrLEDD4WAU6jQb1iDekC8P0DedW4SqkjbV8bcYiKUD2FfHTPstLHmHbbp0B4Q/YGhLU3FyuhD+b443Q2X1UpWXyxr4xcouitSH88a3MVUL0Ah4RmBXNAXKsUU3okP5epYJzZUHJRyBQO8+8ZsSyayS9nXV1vPDAc=
```

Decoding from base64 is not useful. It's just a binary gibberish. I decoded all files but found nothing.
Next, I did a frequency analysis. Data looks very random (or encrypted).

Let's check the second archive:
```
$ unzip -l package2.zip         
Archive:  package2.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
      172  11-24-2020 09:07   0000.bin
      172  11-24-2020 09:07   0001.bin
      172  11-24-2020 09:07   0002.bin
      172  11-24-2020 09:07   0003.bin
...
      172  11-24-2020 09:07   0099.bin
      172  11-24-2020 09:25   flag.bin
---------                     -------
    17372                     101 files
```

Cool, there's the flag! Unfortunately, the archive is **password protected**.

Except the flag, the archives _seems_ to contain the same files ...

How to crack the archive? The answer is here https://delaat.net/rp/2014-2015/p57/presentation.pdf. 
Known plaintext attack on encrypted ZIP files is really an interesting technique!

I chose [pkcrack](https://github.com/keyunluo/pkcrack) for the job:

```
$ ./pkcrack -C package2.zip -c 0000.bin -P package1.zip -p 0000.bin -d decrypted.zip
Files read. Starting stage 1 on Thu Dec  3 19:30:06 2020
Generating 1st generation of possible key2_170 values...done.
Found 4194304 possible key2-values.
Now we're trying to reduce these...
Done. Left with 46493 possible Values. bestOffset is 24.
Stage 1 completed. Starting stage 2 on Thu Dec  3 19:30:16 2020
Stage 2 completed. Starting zipdecrypt on Thu Dec  3 19:58:50 2020
No solutions found. You must have chosen the wrong plaintext.
Finished on Thu Dec  3 19:58:50 2020
```

> _You must have chosen the wrong plaintext._ 

Ok, there are much more files so maybe we just need to use a different one.

Let's check the files a bit more thoroughly this time:
```
unzip -lv package1.zip
Archive:  package1.zip
 Length   Method    Size  Cmpr    Date    Time   CRC-32   Name
--------  ------  ------- ---- ---------- ----- --------  ----
     172  Defl:N      159   8% 11-24-2020 09:07 d1380cc4  0000.bin
     172  Defl:N      158   8% 11-24-2020 09:07 3cea7f5e  0001.bin
     172  Defl:N      158   8% 11-24-2020 09:07 b69fa5a2  0002.bin
     172  Defl:N      157   9% 11-24-2020 09:07 fa93c127  0003.bin
...
     172  Defl:N      159   8% 11-24-2020 09:07 8fe8af52  0099.bin
--------          -------  ---                            -------
   17200            15827   8%                            100 files

$ unzip -lv package2.zip
Archive:  package2.zip
 Length   Method    Size  Cmpr    Date    Time   CRC-32   Name
--------  ------  ------- ---- ---------- ----- --------  ----
     172  Defl:N      159   8% 11-24-2020 09:07 12df6163  0000.bin
     172  Defl:N      158   8% 11-24-2020 09:07 2ec39f7a  0001.bin
     172  Defl:N      159   8% 11-24-2020 09:07 842dfdfe  0002.bin
     172  Defl:N      159   8% 11-24-2020 09:07 fb397508  0003.bin
...
     172  Defl:N      157   9% 11-24-2020 09:07 84766d96  0099.bin
     172  Defl:N       87  49% 11-24-2020 09:25 6f8031cd  flag.bin
--------          -------  ---                            -------
   17372            15908   8%                            101 files
```

CRCs are different.. That explain why the first attempt failed. Hopefully, there are two same files.

```
$ unzip -lv package1.zip | awk '{print $7}' > crcs.txt
$ unzip -lv package2.zip | awk '{print $7}' >> crcs.txt
$ cat crcs.txt | sort | uniq -c
   1 f9c8b013
   1 fa93c127
   1 fb397508
   1 fc54c1b2
   2 fcd6b08a
   1 fd0f8436
   1 fe02137a
```

Nice, there is one overlap!

```
$ unzip -lv package1.zip | grep fcd6b08a
     172  Defl:N      159   8% 11-24-2020 09:07 fcd6b08a  0053.bin
```

Run _pkrack_ again with `0053.bin`:

```
$ ./pkcrack -C package2.zip -c 0053.bin -P package1.zip -p 0053.bin -d decrypted.zip
Files read. Starting stage 1 on Thu Dec  3 13:58:16 2020
Generating 1st generation of possible key2_170 values...done.
Found 4194304 possible key2-values.
Now we're trying to reduce these...
Done. Left with 51026 possible Values. bestOffset is 24.
Stage 1 completed. Starting stage 2 on Thu Dec  3 13:58:26 2020
Ta-daaaaa! key0=2445b967, key1=cfb14967, key2=dceb769b
Probabilistic test succeeded for 151 bytes.
Strange... had a false hit.
Strange... had a false hit.
Strange... had a false hit.
Strange... had a false hit.
Strange... had a false hit.
Stage 2 completed. Starting zipdecrypt on Thu Dec  3 14:37:34 2020
Decrypting 0000.bin (9ad4a32d5536280b9ed5e112)... OK!
Decrypting 0001.bin (e4a90abe31c7fa5cd060b92e)... OK!
Decrypting 0002.bin (32f291521900c30efd341884)... OK!
Decrypting 0003.bin (94b0455afe5d924d351932fb)... OK!
...
Decrypting 0099.bin (46b423aac46dfa48714b7084)... OK!
Decrypting flag.bin (ac980a0f8354fc606be26b6f)... OK!
Finished on Thu Dec  3 14:37:34 2020
```

Yay! Get the flag:

```
$ unzip decrypted.zip flag.bin
$ cat flag.bin | base64 -d
HV20{ZipCrypt0_w1th_kn0wn_pla1ntext_1s_easy_t0_decrypt}
```
