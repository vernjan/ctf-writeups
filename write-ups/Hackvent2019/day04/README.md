# HV19.04 password policy circumvention
_Santa released a new password policy (more than 40 characters, upper, lower, digit, special)._
 
_The elves can't remember such long passwords, so they found a way to continue to use their old (bad) password:_

`merry christmas geeks`

[HV19-PPC.zip](HV19-PPC.zip)

---

Download, unzip and you will find [Autohotkey](https://www.autohotkey.com/) script [HV19-PPC.ahk](HV19-PPC.ahk):
```
::merry::
FormatTime , x,, MM MMMM yyyy
SendInput, %x%{left 4}{del 2}+{right 2}^c{end}{home}^v{home}V{right 2}{ASC 00123}
return

::christmas::
SendInput HV19-pass-w0rd
return

:*?:is::
Send - {del}{right}4h

:*?:as::
Send {left 8}rmmbr{end}{ASC 00125}{home}{right 10}
return

:*?:ee::
Send {left}{left}{del}{del}{left},{right}e{right}3{right 2}e{right}{del 5}{home}H{right 4}
return

:*?:ks::
Send {del}R3{right}e{right 2}3{right 2} {right 8} {right} the{right 3}t{right} 0f{right 3}{del}c{end}{left 5}{del 4}
return

::xmas::
SendInput, -Hack-Vent-Xmas
return

::geeks::
Send -1337-hack
return
```

I installed AutoHotkey and executed the script. The script runs in background
and waits for "hot" sequences to get triggered. The hot sequences are well known: `merry christmas geeks`.

I opened a text editor and typed `merry`. AutoHotkey triggered the logic and rewrote it to `HV19{12 prosinec 19`.
Awesome, but I guess that Czech locale is not expected here.. Changed my OS to _English (USA)_ and tried again.
This time I got `HV19{12 December 19`. The last step is to SLOWLY type the rest of the password.
 
The flag is `HV19{R3memb3r, rem3mber - the 24th 0f December}`