encrypt() { // sub_400b8d
  puts("WhiteBox Test");
  printf("Enter Message to encrypt: ");
  
  char *plainText;
  fgets(plainText, 0x200, stdin); // 512
  plaintTextLength = strlen(plainText) - 1;

  // add padding (PKCS#7)
  uVar3 = (uint)(local_14 >> 0x1f) >> 0x1c;
  int paddingSize = 16 - ((plaintTextLength + uVar3 & 0xf) - uVar3);
  int i = 0;
  while (i < paddingSize) {
    plainText[ plaintTextLength + i ] = (char)paddingSize;
    i++;
  }
  
  // encrypt all blocks
  blockCount = (plaintTextLength / 16) + 1;
  int j = 0;
  while (j < blockCount) {
    encryptBlock(plainText + (j * 16));
    j++;
  }
  
  printHex(plainText, blockCount * 16); // TODO pritint "plaint text" - it's not PT anymore
  
  putchar(0xa); // new line
  return 0;
}

undefined8 encryptBlock(undefined8 *block) { // sub_400b0d
  undefined local_28 [28];
  
  FUN_00400735(block, local_28); // sub_400735
  
  int i = 0;
  while (i < 9) { // 9 times
    FUN_00400812(local_28);
    FUN_00400947(i, local_28);
    i++;
  }
  
  FUN_00400812(local_28);
  FUN_00400a7a(local_28);
  FUN_004007a5(local_28, block);
  
  return block;
}

// TODO FUN_00400735
void FUN_00400735(long lParm1,long lParm2)

{
  int local_10;
  int local_c;

  local_c = 0;
  while (local_c < 4) {
    local_10 = 0;
    while (local_10 < 4) {
      *(undefined *)(lParm2 + (long)local_c * 4 + (long)local_10) =
           *(undefined *)(lParm1 + (long)(local_c + local_10 * 4));
      local_10 = local_10 + 1;
    }
    local_c = local_c + 1;
  }
  return;
}

void FUN_00400812(long lParm1)

{
  undefined uVar1;

  uVar1 = *(undefined *)(lParm1 + 4);
  *(undefined *)(lParm1 + 4) = *(undefined *)(lParm1 + 5);
  *(undefined *)(lParm1 + 5) = *(undefined *)(lParm1 + 6);
  *(undefined *)(lParm1 + 6) = *(undefined *)(lParm1 + 7);
  *(undefined *)(lParm1 + 7) = uVar1;
  uVar1 = *(undefined *)(lParm1 + 8);
  *(undefined *)(lParm1 + 8) = *(undefined *)(lParm1 + 10);
  *(undefined *)(lParm1 + 10) = uVar1;
  uVar1 = *(undefined *)(lParm1 + 9);
  *(undefined *)(lParm1 + 9) = *(undefined *)(lParm1 + 0xb);
  *(undefined *)(lParm1 + 0xb) = uVar1;
  uVar1 = *(undefined *)(lParm1 + 0xc);
  *(undefined *)(lParm1 + 0xc) = *(undefined *)(lParm1 + 0xf);
  *(undefined *)(lParm1 + 0xf) = *(undefined *)(lParm1 + 0xe);
  *(undefined *)(lParm1 + 0xe) = *(undefined *)(lParm1 + 0xd);
  *(undefined *)(lParm1 + 0xd) = uVar1;
  return;
}

void FUN_00400947(int iParm1,long lParm2)

{
  undefined auStack56 [24];
  int local_20;
  int local_1c;
  int local_18;
  int local_14;
  uint local_10;
  int local_c;

  local_c = 0;
  while (local_c < 4) {
    local_10 = 0;
    local_14 = 0;
    while (local_14 < 4) {
      local_10 = local_10 ^
                 *(uint *)(&DAT_00603060 +
                          ((long)(int)(uint)*(byte *)((long)local_14 * 4 + lParm2 + (long)local_c) +
                          ((long)local_c + ((long)iParm1 * 4 + (long)local_14) * 4) * 0x100) * 4);
      local_14 = local_14 + 1;
    }
    local_18 = 0;
    while (local_18 < 4) {
      auStack56[(long)local_c + (long)local_18 * 4] =
           (char)(local_10 >> ((byte)(local_18 << 3) & 0x1f));
      local_18 = local_18 + 1;
    }
    local_c = local_c + 1;
  }
  local_1c = 0;
  while (local_1c < 4) {
    local_20 = 0;
    while (local_20 < 4) {
      *(undefined *)((long)local_1c * 4 + lParm2 + (long)local_20) =
           auStack56[(long)local_20 + (long)local_1c * 4];
      local_20 = local_20 + 1;
    }
    local_1c = local_1c + 1;
  }
  return;
}

void FUN_00400812(long lParm1)

{
  undefined uVar1;

  uVar1 = *(undefined *)(lParm1 + 4);
  *(undefined *)(lParm1 + 4) = *(undefined *)(lParm1 + 5);
  *(undefined *)(lParm1 + 5) = *(undefined *)(lParm1 + 6);
  *(undefined *)(lParm1 + 6) = *(undefined *)(lParm1 + 7);
  *(undefined *)(lParm1 + 7) = uVar1;
  uVar1 = *(undefined *)(lParm1 + 8);
  *(undefined *)(lParm1 + 8) = *(undefined *)(lParm1 + 10);
  *(undefined *)(lParm1 + 10) = uVar1;
  uVar1 = *(undefined *)(lParm1 + 9);
  *(undefined *)(lParm1 + 9) = *(undefined *)(lParm1 + 0xb);
  *(undefined *)(lParm1 + 0xb) = uVar1;
  uVar1 = *(undefined *)(lParm1 + 0xc);
  *(undefined *)(lParm1 + 0xc) = *(undefined *)(lParm1 + 0xf);
  *(undefined *)(lParm1 + 0xf) = *(undefined *)(lParm1 + 0xe);
  *(undefined *)(lParm1 + 0xe) = *(undefined *)(lParm1 + 0xd);
  *(undefined *)(lParm1 + 0xd) = uVar1;
  return;
}

void FUN_00400a7a(long lParm1)

{
  int local_10;
  int local_c;

  local_c = 0;
  while (local_c < 4) {
    local_10 = 0;
    while (local_10 < 4) {
      *(undefined *)((long)local_c * 4 + lParm1 + (long)local_10) =
           (&DAT_00602060)
           [(long)(int)(uint)*(byte *)((long)local_c * 4 + lParm1 + (long)local_10) +
            ((long)local_10 + (long)local_c * 4) * 0x100];
      local_10 = local_10 + 1;
    }
    local_c = local_c + 1;
  }
  return;
}

void FUN_004007a5(long lParm1,long lParm2)

{
  int local_10;
  int local_c;

  local_c = 0;
  while (local_c < 4) {
    local_10 = 0;
    while (local_10 < 4) {
      *(undefined *)(lParm2 + (long)(local_c + local_10 * 4)) =
           *(undefined *)((long)local_c * 4 + lParm1 + (long)local_10);
      local_10 = local_10 + 1;
    }
    local_c = local_c + 1;
  }
  return;
}

void printHex(long *plainText,int totalSize) { // sub_400677
  int i = 0;
  while (i < totalSize) {
    printf("%02x",(ulong)((int)*(char *)(plainText + (long)i) & 0xff));
    i++;
  }
  return;
}