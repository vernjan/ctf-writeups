# Problematic Executables

Hi Expert,

some unhappy archeaologist tells you about her problems with examination of some executable - it always ends with `Alarm! Bad usage! Alarm!`. Luckily, part of the original code was retrieved, but no cuneiform, hieroglyphs or cat pictures were present, so the archeaologist cannot understand it. Prove you skill and found how to run the executable.

Download the file [executables.zip](executables.zip) (sha256 fingerprint: `65815f77939e3580444e10154b72252953091694cd243ded72b9c8e1cdc0d722`).

---

Firstly, read `executable_code.part`:

```c
int main(int argc, char *argv[]) {
  int num;

  if (argc != 4){
    printf("Alarm! Bad usage! Alarm!\n");
    return 1;
  }
  if (strcmp(argv[1], "show-me-the-secret") != 0 || strcmp(argv[2], "please") != 0){
    printf("Alarm! Bad usage! Alarm!\n");
    return 1;
  }
  num = atoi(argv[3]);
  if (num < 4 || num > 7){
    printf("Alarm! Bad usage! Alarm!\n");
    return 1;
  }

  print_secret(num);
  return 0;
}
```

We just need to provide the correct arguments, namely `show-me-the-secret please [4-7]`. 

```
>executable.exe show-me-the-secret please 6
Good usage!
FLAG{mbK4-xd0U-cNip-36tm}
```

---

## Afraid to run the executable?

Windows 10 is reporting `executable.zip` as malicious. Namely, it says the file
contains `Trojan:Script/Phonzy.C!ml` and moves the file into quarantine.
[VirusTotal report](https://www.virustotal.com/gui/file/b1f49d9fae446e3804e5ec7c588e06664431b9a0d35ce25a3fbcb514e83a835e) report is also not clean.

I discovered a very useful built-in feature of Windows 10 - [Windows Sandbox](https://techcommunity.microsoft.com/t5/windows-kernel-internals/windows-sandbox/ba-p/301849).

You can safely run unknown executables using the sandbox.