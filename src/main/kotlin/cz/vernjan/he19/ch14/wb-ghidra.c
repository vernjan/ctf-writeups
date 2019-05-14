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
  undefined some [28];
  
  copyAndSwapRowsWithColumns(block, some); // sub_400735
  
  int i = 0;
  while (i < 9) { // 9 times
    shiftRows(some);
    FUN_00400947(i, some);
    i++;
  }
  
  shiftRows(some);
  readFrom0x602060(some); // lookup encrypted bytes in the DATA section
  copyAndReverseSwapRowsWithColumns(some, block); // rewrites plain text with the encrypted version
  
  return block;
}

// byte by byte ..
// 0 -> 0
// 1 -> 4
// 2 -> 8
// 3 -> c

// 4 -> 1
// 5 -> 5
// 6 -> 9
// 7 -> d

// 8 -> 2
// 9 -> 6
// a -> a
// b -> e

// c -> 3
// d -> 7
// e -> b
// f -> f

// 0, 1, 2, 3
// 4, 5, 6, 7
// 8, 9, a, b
// c, d, e, f

// 0, 4, 8, c
// 1, 5, 9, d
// 2, 6, a, e
// 3, 7, b, f


void shiftRows(long *some) { // 400812

  undefined temp;

  // shift 2nd row by 1
  temp = *(some + 4);
  *(some + 4) = *(some + 5);
  *(some + 5) = *(some + 6);
  *(some + 6) = *(some + 7);
  *(some + 7) = temp;
  
  // shift 3rd row by 2
  temp = *(some + 8);
  *(some + 8) = *(some + 10);
  *(some + 10) = temp;
  temp = *(some + 9);
  *(some + 9) = *(some + 0xb);
  *(some + 0xb) = temp;
  
  // shift 4th row by 3
  temp = *(some + 0xc);
  *(some + 0xc) = *(some + 0xf);
  *(some + 0xf) = *(some + 0xe);
  *(some + 0xe) = *(some + 0xd);
  *(some + 0xd) = temp;
  
  return;
}

void FUN_00400947(int iParm1,long lParm2) {
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



void readFrom0x602060(long *some) { // 400a7a
  int i = 0;
  while (i < 4) {
    int j = 0;
    while (j < 4) {
    // FIXME rewrite so this makes sense (once I'm sure about it)
      *(some + i * 4 + j) = (&DAT_00602060) [*(byte *) (some + i * 4 + j) + (i * 4 + j) * 0x100]; // 256 // TODO maybe this is a value from some .. ! WOULD MAKE SENSE: DATA[some[i] + 256*i] YES: 512*256 = 131,072
      j++;
    }
    i++;
  }
}

void copyAndSwapRowsWithColumns(long *block,long *some) { // 400735
  int i = 0;
  while (i < 4) {
    int j = 0;
    while (j < 4) {
      *(some + i * 4 + j) = *(block + i + j * 4);
      j++;
    }
    i++;
  }
}

void copyAndReverseSwapRowsWithColumns(long *some,long *block) { // 4007a5
  int i = 0;
  while (i < 4) {
    int j = 0;
    while (j < 4) {
      *(block + i + j * 4) = *(some + i * 4 + j);
      j++;
    }
    i++;
  }
}

void printHex(long *plainText,int totalSize) { // 400677
  int i = 0;
  while (i < totalSize) {
    printf("%02x",(ulong)((int)*(char *)(plainText + (long)i) & 0xff));
    i++;
  }
  return;
}