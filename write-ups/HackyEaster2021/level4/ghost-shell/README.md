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


ssh 46.101.107.117 -p 2106 -l inky

scp -r -P 2106 inky@46.101.107.117:/home/inky/  /mnt/d/

find / -xdev -type f -print0 | xargs -0 grep -Hi "flag!"
