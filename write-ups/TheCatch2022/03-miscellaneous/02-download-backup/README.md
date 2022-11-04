# Download backup

Hi, packet inspector,

our former employee Brenda (head of PR department) was working on new webpage with superdiscount code for VIP customers,
but she get fired by AI because of "disturbing lack of machine precision".

Your task is to find the code as soon as possible. The only hope is an automated backup of Brenda's `Download`
directory (
there is a high probability that she had downloaded the discount page or part of it).

Download [the backup file](download_backup.zip) (MD5 checksum `2fd749e99a0237f506a0eb3e81633ad7`).

May the Packet be with you!

---

I downloaded and unrar the archive. There are some files:

```
$ file *
1098612x18781390.pdf:            PDF document, version 1.3
img.png:                         PNG image data, 2451 x 3492, 8-bit/color RGB, interlaced
thecatch2022-form-header.png:    PNG image data, 1500 x 500, 8-bit/color RGBA, non-interlaced
xDracula_08-03-2012.jpg:         JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, comment: "CREATOR: gd-jpeg v1.0 (using IJG JPEG v62), quality = 76", baseline, precision 8, 700x508, components 3
```

I started looking in `img.png` because this is the design page for the mentioned new webpage.
Unfortunately, I couldn't find anything. Then I took the official hint:

```
Brenda's favorite browser was MS Edge, i.e. she used MS Windows (running the filesystem NTFS).
```

Ok, I was looking at the wrong place. I shifted my focus on NTFS steganography and find this great article
[Hiding In Plain Sight With NTFS Steganography](https://www.secjuice.com/ntfs-steganography-hiding-in-plain-sight/.).

I learnt about [NTFS File Streams](https://stealthbits.com/blog/ntfs-file-streams/).

You can view ASDs with `dir /r`:

```
> dir /r
 Volume in drive C is SYSTEM
 Volume Serial Number is 48D5-9204

 Directory of C:\Users\vernj\Downloads\Download

16.10.2022  12:08    <DIR>          .
16.10.2022  12:08    <DIR>          ..
08.08.2022  13:45        14 839 798 1098612x18781390.pdf
                                539 1098612x18781390.pdf:Zone.Identifier:$DATA
08.08.2022  13:41           834 077 img.png
                                161 img.png:Zone.Identifier:$DATA
08.08.2022  13:44            55 385 thecatch2022-form-header.png
                                127 thecatch2022-form-header.png:Zone.Identifier:$DATA
08.08.2022  13:42            67 811 xDracula_08-03-2012.jpg
                                172 xDracula_08-03-2012.jpg:Zone.Identifier:$DATA
               4 File(s)     15 797 071 bytes
               2 Dir(s)  118 628 970 496 bytes free
```

You can read ADS with `more`. We are interested in `img.png:Zone.Identifier` stream:
```
> more < img.png:Zone.Identifier
[ZoneTransfer]
ZoneId=3
ReferrerUrl=http://self-service.mysterious-delivery.thecatch.cz/
HostUrl=http://self-service.mysterious-delivery.thecatch.cz/img.png
```

Finally, visit http://self-service.mysterious-delivery.thecatch.cz/:

![](img-solved.png)

Flag is `FLAG{16bd-0c4x-ZRJe-8HC3}`
