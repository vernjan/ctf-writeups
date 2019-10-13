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

Let's start with the basics:
```
$ file seventh_element.dd 
seventh_element.dd: DOS/MBR boot sector; partition 1 : ID=0xee, start-CHS (0x0,0,2), end-CHS (0x20,227,3), startsector 1, 528383 sectors, extended partition table (last)
```

Indeed, this looks a like a copy of a flash drive. Now it's time to find out what it contains.
```
$ fdisk -l seventh_element.dd 
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
...
seventh_element.dd128 522240 526335    4096   2M Linux filesystem
```

The flash drive is split into 128 partitions.. We need to set up
[loop devices](https://en.wikipedia.org/wiki/Loop_device) before we can mount them.
```
$ losetup -P -f seventh_element.dd
```
The `-P` option is very useful in this case. It _forces the kernel to scan the partition table on
a newly created loop device_. No need to count partitions offsets by hand.
``` 
$ lsblk
NAME        MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
loop3         7:3    0  258M  0 loop 
├─loop3p1   259:0    0    2M  0 loop /home/vernjan/seventh/part1
├─loop3p2   259:1    0    2M  0 loop /home/vernjan/seventh/part2
├─loop3p3   259:2    0    2M  0 loop /home/vernjan/seventh/part3
├─loop3p4   259:3    0    2M  0 loop /home/vernjan/seventh/part4
├─loop3p5   259:4    0    2M  0 loop /home/vernjan/seventh/part5
├─loop3p6   259:5    0    2M  0 loop /home/vernjan/seventh/part6
...
└─loop3p128 259:127  0    2M  0 loop /home/vernjan/seventh/part128
```

Good. Now mount the all!
```
$ for i in {1..128}; do
> mkdir part$i
> sudo mount /dev/loop3p$i part$i
> done
```

And finally, let's see what's hidden inside.
```
$ tree -a
.
├── part1
│   └── .file
├── part10
│   └── .file
├── part100
│   └── .file
├── part101
│   └── .file
├── part102
│   └── .file
├── part103
│   └── .file
├── part104
│   └── .file
...
└── part99
    └── .file
```

Each mounted partition contains a single hidden file `.file`. The only exceptions are partitions
**66** and **82** which are empty!

What's inside of those files..
```
$ part1/.file
6865
0x1b
$ part2/.file
6e21
0x6d
```

Apparently, a message was split into pieces and one piece was saved into each partition in a random order.
The first line (2 ASCII encoded chars) is a part of the message and the second line (hex number) points to
the next part of the message.

I searched for string `FL` and confirmed that it points to `AG`. It would be quite easy to recover the
flag by hand but I was keen to get the whole message.

The first step was to grep all message pieces.
```
$ find . -type f -printf "%T@ %p\n" | sort -n | cut -d ' ' -f2 | xargs cat {} \;
6865
0x1b
6e21
0x6d
7179
0x2c
5225
0x64
7931
0x3e
...
```

Then I wrote a [Kotlin program](../../../../src/main/kotlin/cz/vernjan/ctf/catch19/SeventhElement.kt) 
to recover the full message.

Actually, there are 2 messages (2 cycles):
```
WARNING{Indexing from 1? Are you pathetic human?} .'3a|7ZCbHU[`waP[JoHdKj5bdMWB$tR#5s\MV?ORZ|GHx4l9;d6_2iR$Y1I_CPPMv3/u;R%stA=qy:W6@Pn\r"fD+}09<][ Nmj,@>Evyn!IP]qTL-0wtHo_$ofW'<=Y=QH-4-N^lf9S2VjW4X#6G8PHUuY*?y1'\&/o2(bBru6U1? 
FLAG{tPJ4-idCH-GWlh-JjL8} 
```