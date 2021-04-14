# Ghost in a Shell 2
```
_, _,_  _,  _, ___   _ _, _    _,    _, _,_ __, _,  _,    ,  ,  
/ _ |_| / \ (_   |    | |\ |   /_\   (_  |_| |_  |   |     |  |  
\ / | | \ / , )  |    | | \|   | |   , ) | | |   | , | ,   |  |  
~  ~ ~  ~   ~   ~    ~ ~  ~   ~ ~    ~  ~ ~ ~~~ ~~~ ~~~   ~  ~
______________________________________________________________________  
,--.     ,--.    
| oo |   | oo |   
| ~~ |   | ~~ |   o  o  o  o  o  o  o  o  o  o  o  o  o  o  o  o  o  
|/\/\|   |/\/\|
______________________________________________________________________  
```

Connect to the server, snoop around, and find the flag!

- `ssh 46.101.107.117 -p 2108 -l clyde`
- password is: `555-ClYdE`

---

The home dir contains hidden dir `.lost+found`:
```
7b18a234d2a8:~$ ls -la .lost\+found/
total 16
-r--r-----    1 root     pacman          32 Apr 14 20:00 flag.txt
```

Looks like a real flag. However, it's owned by another user (`pacman`).

Let's see what's in `pacman` home:
```
7b18a234d2a8:/home/pacman$ ls -la
total 28
-rwxr-xr-x    1 root     root             9 Apr 14 20:00 ."\?$*'N'*$?\"
-rwxr-xr-x    1 root     root           312 Mar  2 12:05 .bash_history
-rwxr-xr-x    1 root     root           277 Mar  2 12:05 notes.txt
```

```
.$'N'$
```

msPACM4n


b17af3d00ffc:~/.lost+found$ sg pacman -c 'cat flag.txt'
Password:
he2021{wh4ts_y0ur_grewp_4g4in?}