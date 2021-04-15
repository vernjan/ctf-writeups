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
-r--r-----    1 root     pacman          32 Apr 14 20:00 flag.txt
```

Looks like a real flag (size 32). However, it's owned by `root` and group `pacman`.

Let's see what's in `pacman` home:
```
7b18a234d2a8:/home/pacman$ ls -la
-rwxr-xr-x    1 root     root             9 Apr 14 20:00 ."\?$*'N'*$?\"
-rwxr-xr-x    1 root     root           312 Mar  2 12:05 .bash_history
-rwxr-xr-x    1 root     root           277 Mar  2 12:05 notes.txt
```

There are two interesting files. The first one with super weird name `."\?$*'N'*$?\"` and then `.bash_history`.

I didn't know how to read `."\?$*'N'*$?\"` but once I `scp` the whole pacman's home folder into my Windows machine, it
got renamed automatically, and I was able to read it easily. The content is: `msPACM4n`. Looks like a password!

At first, I tried to SSH to this server as `pacman` using this password, but it was not accepted.

Now comes the time for `.bash_history` file. There is some garbage but one of the commands is `man sg`.
I had no idea what `sg` command is good for until I googled it:
> Execute command as different group ID

Okay! Let's try this:
```
b17af3d00ffc:~/.lost+found$ sg pacman -c 'cat flag.txt'
Password:
he2021{wh4ts_y0ur_grewp_4g4in?}
```

The flag is `he2021{wh4ts_y0ur_grewp_4g4in?}`