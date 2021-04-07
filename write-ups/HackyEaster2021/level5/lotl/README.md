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

Here we go, `segfault`.

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