# Seventh element (4p)
_Hi Commander,_

_thanks to your discovery of the drone as a false target, our radars could concentrate on the detection
of the second drone. This one was classic quadcopter and our trained falcon has caught it up and took
it off the sky. The last broadcast was `Seventh element down, malfunction due claws and beak in propellers.`
The wreck has been completely shattered and just one operational flash drive has been rescued from the
crashsite. According to the intelligence, we believe that the drone was ordered to transport some coded
message to the elementary school library in city of Ostrava in order to create backup uprising centre.
You have to analyse the content of the drive and decode the message._

_Good luck!_

[seventh_element.dd.gz](seventh_element.dd.gz)

---

```
$ file seventh_element.dd 
seventh_element.dd: DOS/MBR boot sector; partition 1 : ID=0xee, start-CHS (0x0,0,2), end-CHS (0x20,227,3), startsector 1, 528383 sectors, extended partition table (last)
```

```
$ fdisk -l seventh_element.dd 
fdisk -l seventh_element.dd
Disk seventh_element.dd: 258 MiB, 270532608 bytes, 528384 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: gpt
Disk identifier: 084E5312-16B8-4995-9D3B-F4A7046FD9F4

Device                 Start    End Sectors Size Type
seventh_element.dd1     2048   6143    4096   2M Linux filesystem
seventh_element.dd2     6144  10239    4096   2M Linux filesystem
seventh_element.dd3    10240  14335    4096   2M Linux filesystem
seventh_element.dd4    14336  18431    4096   2M Linux filesystem
seventh_element.dd5    18432  22527    4096   2M Linux filesystem
seventh_element.dd6    22528  26623    4096   2M Linux filesystem
seventh_element.dd7    26624  30719    4096   2M Linux filesystem
seventh_element.dd8    30720  34815    4096   2M Linux filesystem
seventh_element.dd9    34816  38911    4096   2M Linux filesystem
seventh_element.dd10   38912  43007    4096   2M Linux filesystem
seventh_element.dd11   43008  47103    4096   2M Linux filesystem
seventh_element.dd12   47104  51199    4096   2M Linux filesystem
seventh_element.dd13   51200  55295    4096   2M Linux filesystem
seventh_element.dd14   55296  59391    4096   2M Linux filesystem
seventh_element.dd15   59392  63487    4096   2M Linux filesystem
...
seventh_element.dd128 522240 526335    4096   2M Linux filesystem

```

$losetup -P -f seventh_element.dd

```
lsblk
NAME        MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
loop0         7:0    0  258M  0 loop 
├─loop0p1   259:0    0    2M  0 part /media/root/0x00
├─loop0p2   259:1    0    2M  0 part /media/root/0x01
├─loop0p3   259:2    0    2M  0 part /media/root/0x02
├─loop0p4   259:3    0    2M  0 part /media/root/0x03
├─loop0p5   259:4    0    2M  0 part /media/root/0x04
├─loop0p6   259:5    0    2M  0 part /media/root/0x05
├─loop0p7   259:6    0    2M  0 part /media/root/0x06
├─loop0p8   259:7    0    2M  0 part /media/root/0x07
├─loop0p9   259:8    0    2M  0 part /media/root/0x08
├─loop0p10  259:9    0    2M  0 part /media/root/0x09
├─loop0p11  259:10   0    2M  0 part /media/root/0x0a
├─loop0p12  259:11   0    2M  0 part /media/root/0x0b
├─loop0p13  259:12   0    2M  0 part /media/root/0x0c
├─loop0p14  259:13   0    2M  0 part /media/root/0x0d
├─loop0p15  259:14   0    2M  0 part /media/root/0x0e
├─loop0p16  259:15   0    2M  0 part /media/root/0x0f
├─loop0p17  259:16   0    2M  0 part /media/root/0x10
├─loop0p18  259:17   0    2M  0 part /media/root/0x11
├─loop0p19  259:18   0    2M  0 part /media/root/0x12
...

```

find /media/root/ -type f -exec cat {} \; > pieces.txt

66 a 82 empty ..