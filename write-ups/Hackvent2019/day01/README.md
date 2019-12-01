# HV19.01 censored

_I got this little image, but it looks like the best part got censored on the way.
Even the tiny preview icon looks clearer than this! Maybe they missed something that
would let you restore the original content?_

![](censored.jpg)

---

I analyzed the image with online tool [Forencisally](https://29a.ch/photo-forensics).
Just click on _Thumbnail analysis_ and it's done:

![](thumbnail.png)

---
More sophisticated way is to extract the thumbnail with `exiftool`:

```
$ exiftool censored.jpg
...
Thumbnail Image : (Binary data 5336 bytes, use -b option to extract)

$ exiftool -b -ThumbnailImage censored.jpg > thumbnail-exiftool.jpg
```
Here is the output (just zoom in to get readable QR code):

![](thumbnail-exiftool.jpg)

The flag is `HV19{just-4-PREview!}`