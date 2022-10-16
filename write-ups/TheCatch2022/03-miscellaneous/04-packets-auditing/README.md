# Packets auditing

Hi, packet inspector,

the AI has "upgraded" our packet auditing system – time to time, it generates archive of pictures, where the state of
packet and the appropriate delivery team is indicated by different colours for each packet transport number.

We have a plea from `Brenda's delivery team` to find their missing packet in state `ready for pickup` (the other teams
have
already delivered all their packages mentioned in last given audit archive).

Download _audit archive_ (MD5 checksum `08ee155d2c9aee13ea5cab0a11196129`), find the desired pickup code and enter it on
webpage http://pickup.mysterious-delivery.thecatch.cz to collect pickup code.

May the Packet be with you!

---

The archive contains ~25,000 PNG images.

This is the `description` image:

![](description.png)

And example of packet image

![](000000.png)

Our goal is to find a package from Brenda's team in `Readt for pickup` state, i.e. an image
with **green package** and **orange background**.

```python
import os

import imageio.v3 as iio

RGB_GREEN = [0, 133, 71]
RGB_ORANGE = [242, 121, 48]

for dir_path, dirs, files in os.walk('packet_images'):
    for filename in files:
        file_path = os.path.join(dir_path, filename)

        img = iio.imread(file_path)

        bg_color = img[0][0].tolist()
        package_color = img[125][125].tolist()

        if bg_color == RGB_ORANGE and package_color == RGB_GREEN:
            print(file_path)
```

The desired package is `2022-08\30\19\000000.png`:

![](000000-correct.png)

The flag is `FLAG{rNM8-Aa5G-dF5y-6LqY}`