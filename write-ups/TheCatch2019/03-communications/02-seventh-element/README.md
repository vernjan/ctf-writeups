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
Yes, that looks a like a copy of flash drive.

```
$ file seventh_element.dd 
seventh_element.dd: DOS/MBR boot sector; partition 1 : ID=0xee, start-CHS (0x0,0,2), end-CHS (0x20,227,3), startsector 1, 528383 sectors, extended partition table (last)
vernjan@vernjan-VirtualBox:~/sf_Shared$ fdisk -l seventh_element.dd 
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
...
seventh_element.dd128 522240 526335    4096   2M Linux filesystem
```

This flash drive is split into 128 partitions.. Let's try to mount them.
```
$ losetup -P -f seventh_element.dd
```
The `-P` option is very useful in this case. It _forces the kernel to scan the partition table on a newly created
loop device_. Let's see how that worked out:
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
├─loop3p7   259:6    0    2M  0 loop /home/vernjan/seventh/part7
├─loop3p8   259:7    0    2M  0 loop /home/vernjan/seventh/part8
├─loop3p9   259:8    0    2M  0 loop /home/vernjan/seventh/part9
├─loop3p10  259:9    0    2M  0 loop /home/vernjan/seventh/part10
...
└─loop3p128 259:127  0    2M  0 loop /home/vernjan/seventh/part128
```
Good. Now it's time to mount the all!
```
$ for i in {1..128}; do
> mkdir part$i
> sudo mount /dev/loop3p$i part$i
> done
```

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

Each mounted partition contains a single hidden file `.file`. The only exceptions are partitions 66 and 82
which are empty!

Let's see what's inside of those files..
```
$ part1/.file
6865
0x1b
$ part2/.file
6e21
0x6d
```

A message was split into pieces and one piece was saved into each partition. 
(first line, 2 ASCII encoded chars)
The hex number (second line) points to the next piece of a message. I search for strings `FL` and confirmed that it
points to `AG`. It would be quite easy to recover the flag by hand but I was curious what else is hidden
so I wrote a Kotlin program to recover the message.

find . -type f -printf "%T@ %p\n" | sort -n | cut -d ' ' -f2 | xargs cat {} \; > pieces.txt


The messages are actually two:
```
WARNING{Indexing from 1? Are you pathetic human?} .'3a|7ZCbHU[`waP[JoHdKj5bdMWB$tR#5s\MV?ORZ|GHx4l9;d6_2iR$Y1I_CPPMv3/u;R%stA=qy:W6@Pn\r"fD+}09<][ Nmj,@>Evyn!IP]qTL-0wtHo_$ofW'<=Y=QH-4-N^lf9S2VjW4X#6G8PHUuY*?y1'\&/o2(bBru6U1? 
FLAG{tPJ4-idCH-GWlh-JjL8} 
```