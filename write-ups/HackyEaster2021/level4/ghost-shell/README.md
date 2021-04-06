# Ghost in a Shell 1
```
_, _,_  _,  _, ___   _ _, _    _,    _, _,_ __, _,  _,    ,  
/ _ |_| / \ (_   |    | |\ |   /_\   (_  |_| |_  |   |     |  
\ / | | \ / , )  |    | | \|   | |   , ) | | |   | , | ,   |  
~  ~ ~  ~   ~   ~    ~ ~  ~   ~ ~    ~  ~ ~ ~~~ ~~~ ~~~   ~
______________________________________________________________________  
,--.    
| oo |   
| ~~ |   o  o  o  o  o  o  o  o  o  o  o  o  o  o  o  o  o  o  o  o  
|/\/\|
______________________________________________________________________  
```

Connect to the server, snoop around, and find the flag!

- `ssh 46.101.107.117 -p 2106 -l inky`
- password is: `mucky_4444`

---

I spent a bit more time on this one but at least I found a funny way how to mess with other players 😅

## The solution

The flag is hidden in the home directory. You just need to look carefully.

```
$ ls -la
drwxr-xr-x    1 root     root          4096 Apr  6 18:00 .
drwxr-xr-x    1 root     root          4096 Apr  3 05:23 ..
-rwxr-xr-x    1 root     root            15 Apr  6 18:00 .bashrc
drwxr-xr-x    1 root     root          4096 Apr  3 05:23 images
-rwxr-xr-x    1 root     root          2183 Feb 27 17:53 notes.txt
drwxr-xr-x    1 root     root          4096 Apr  3 05:23 text
```

Nothing interesting here. Let's look into `images`:
```
drwxr-xr-x    1 root     root          4096 Apr  3 05:23 .
drwxr-xr-x    1 root     root          4096 Apr  6 18:00 ..
drwxr-xr-x    1 root     root          4096 Apr  3 05:23 ...
-rwxr-xr-x    1 root     root         23864 Feb 27 17:53 ghost_1.png
-rwxr-xr-x    1 root     root         25957 Feb 27 17:53 ghost_2.png
-rwxr-xr-x    1 root     root         37335 Feb 27 17:53 ghost_3.png
-rwxr-xr-x    1 root     root         30530 Feb 27 17:53 ghost_4.png
-rwxr-xr-x    1 root     root         27476 Feb 27 17:53 ghost_5.png
-rwxr-xr-x    1 root     root         35378 Feb 27 17:53 ghost_6.png
-rwxr-xr-x    1 root     root         31358 Feb 27 17:53 ghost_7.png
-rwxr-xr-x    1 root     root         32507 Feb 27 17:53 ghost_8.png
-rwxr-xr-x    1 root     root         27413 Feb 27 17:53 ghost_9.png
```

Look at the `...` folder!

```
$ cd ...
$ ls -la
drwxr-xr-x    1 root     root          4096 Apr  3 05:23 .
drwxr-xr-x    1 root     root          4096 Apr  3 05:23 ..
-rwxr-xr-x    1 root     root         20263 Feb 27 17:53 ...
```

No we have `...` file.

I copied all the files to my local machine:
```
$ scp -r -P 2106 inky@46.101.107.117:/home/inky/  /mnt/d/
$ mv ... ../hidden.png
```

![](hidden.png)

The flag is `he2021{h1dd3n_d0td0td0t!}`

## Messing with other players
All players use the same `inky` user. You can, for example:
- send them a message right into their console (`echo hello > /dev/pts/<NUMBER>`)
- read their console (`cat /dev/pts/<NUMBER>`)
- kill their sessions (`ps; kill PID for another sshd: inky@pts/<NUMBER>`)
