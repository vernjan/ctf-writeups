I decompile the game in Ghidra. The code is quite straightforward with the exception of invalid DATA addresses but
the right data can be guessed quite easily.

Here is the code with comments:
```
undefined8 _main(void)

{
  byte bVar1;
  undefined *puVar2;
  undefined *puVar3;
  uint uVar4;
  int iVar5;
  undefined8 uVar6;
  undefined8 uVar7;
  long lVar8;
  long lVar9;
  undefined2 *puVar10;
  code *local_520;
  code *local_518;
  undefined8 local_509;
  undefined local_501;
  undefined2 local_500 [8];
  undefined2 local_4f0;
  undefined2 local_4ee;
  undefined4 local_4ec;
  undefined local_4e6 [6];
  byte local_4e0 [32];
  byte local_4c0 [32];
  undefined local_4a0 [112];
  undefined local_430 [1024];

  (*(code *)refptr.initKernel)();
  (*(code *)refptr.initLibc)();
  (*(code *)refptr.initNetwork)();
  uVar4 = (**(code **)refptr.sceKernelLoadStartModule)(0x2174,0,0,0,0,0);
  puVar3 = refptr.sceKernelDlsym;
  (*(code *)refptr.sceKernelDlsym)((ulong)uVar4,0x219d,&local_520);
  (*(code *)puVar3)((ulong)uVar4,0x21c6,&local_518);
  puVar3 = refptr.malloc;
  uVar6 = (**(code **)refptr.malloc)(0x40);
  uVar7 = (**(code **)puVar3)(0x10);
  (*local_520)(uVar6);
  (*local_518)(uVar7);

  // Open file - Unfortunately, the addresses are for some reasons invalid
  // On the hand, there is only 1 file in DATA so it's not hard to guess it
  // fopen("/mnt/usb0/PS4UPDATE.PUP", "rb")
  uVar6 = (**(code **)refptr.fopen)(0x2234,0x222a);
  lVar8 = (**(code **)puVar3)(0x21);
  (*(code *)refptr.MD5Init)(local_4a0);
  puVar2 = refptr.MD5Update;
  puVar3 = refptr.fread;
  // Get md5 hash of the file
  while( true ) {
    uVar4 = (**(code **)puVar3)(local_430,1,0x400,uVar6);
    if (uVar4 == 0) break; // End of file
    (*(code *)puVar2)(local_4a0,local_430,(ulong)uVar4);
  }
  puVar10 = local_500;
  (*(code *)refptr.MD5Final)(puVar10,local_4a0);
  (**(code **)refptr.fclose)(uVar6);
  puVar2 = refptr.sprintf;
  lVar9 = lVar8;
  // Read from memory the expected md5 hash
  do {
    bVar1 = *(byte *)puVar10;
    puVar10 = (undefined2 *)((long)puVar10 + 1);
    (**(code **)puVar2)(lVar9,0x22d7,(ulong)bVar1);
    lVar9 = lVar9 + 2;
  } while (&local_4f0 != puVar10);
  // Compare the file hash with expected hash "f86d4f9d2c049547bd61f942151ffb55"
  iVar5 = (**(code **)refptr.strcmp)(0x22fe,lVar8);
  // If hashes equal
  if (iVar5 == 0) {
    lVar8 = 0;
    // Read a secret key from memory (starts at 0x2000)
    // It is CE 55 95 4E 38 C5 89 A5 1B 6F 5E 25 D2 1D 2A 2B 5E 7B 39 14 8E D0 F0 F8 F8 A5
    do {
      local_4e0[lVar8] = *(byte *)(lVar8 + 0x229b);
      lVar8 = lVar8 + 1;
    } while (lVar8 != 0x1a);
    // fseek start position
    lVar8 = 0x1337;
    // Open the file again
    uVar6 = (**(code **)refptr.fopen)(0x2322,0x2318);
    do {
      // Read chunks of bytes (length 26) from the file (i * 0x1337 + 0x1337, 26)
      (**(code **)refptr.fseek)(uVar6,lVar8,0);
      (**(code **)puVar3)(local_4c0,0x1a,1,uVar6);
      lVar9 = 0;
      do {
        // XOR the chunk with "secret key" and save the result into "secret key"
        local_4e0[lVar9] = local_4e0[lVar9] ^ local_4c0[lVar9];
        lVar9 = lVar9 + 1;
      } while (lVar9 != 0x1a);
      lVar8 = lVar8 + 0x1337;
    } while (lVar8 != 0x1714908); // Repeat until counter == 0x1714908 (0x1337 steps)
    (**(code **)refptr.fclose)(uVar6);
    local_501 = 0;
    local_509 = 0x67616c66646e6573; // Send flag (over network)
    local_4f0 = 0x210;
    local_4ec = 0x100007f;
    local_4ee = (**(code **)refptr.sceNetHtons)(0x539);
    (**(code **)refptr.memset)(local_4e6,0,6);
    uVar4 = (**(code **)refptr.sceNetSocket)(&local_509,2,1,0);
    (**(code **)refptr.sceNetConnect)((ulong)uVar4,&local_4f0,0x10);
    (**(code **)refptr.sceNetSend)((ulong)uVar4,local_4e0,0x1a,0); // The flag is in local_4e0
    (**(code **)refptr.sceNetSocketClose)((ulong)uVar4);
  }
  return 0;
}
```

I downloaded the file from []() and rewrite the login in Kotlin. See []().

The flag is: ``