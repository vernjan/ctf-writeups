int sub_400b8d(int arg0, int arg1) {

    puts("WhiteBox Test");
    printf("Enter Message to encrypt: ");
    fgets(&plainText, 0x200, *stdin); // 512
    
    rax = strlen(&plainText);
    ptLen = rax - 0x1;
    rax = ptLen;
    rdx = rax + 0xf;
    if (rax < 0x0) {
            rax = rdx;
    }
    
    
    var_14 = (0x10 - (ptLen + ((ptLen & 0x80000000 ? 0xffffffff : 0x0) >> 0x1c) & 0xf)) + ((ptLen & 0x80000000 ? 0xffffffff : 0x0) >> 0x1c);
    for (i = 0x0; i < var_14; i++) {
            *(int8_t *)(rbp + (sign_extend_64(ptLen + i) - 0x220)) = var_14;
    }
    
    // encrypts all blocks
    blockCount = (SAR(rax, 0x4)) + 0x1;
    for (i = 0x0; i < blockCount; i = i + 0x1) {
            encryptBlock((i << 0x4) + &plainText);
    }
    
    // print hex
    printHex(&plainText, blockCount << 0x4); // blockCount * 16
    
    putchar(0xa);
    return 0x0;
}

int encryptBlock(int arg0) {
    var_28 = arg0;
    rax = sub_400735(var_28, &var_20);
    for (i = 0x0; i <= 0x8; i = i + 0x1) {
            sub_400812(&var_20);
            rax = sub_400947(i, &var_20);
    }
    sub_400812(&var_20);
    sub_400a7a(&var_20);
    sub_4007a5(&var_20, var_28);
    rax = var_28;
    return rax;
}

void sub_400735(int arg0, int arg1) {
    var_18 = arg0;
    var_20 = arg1;
    for (var_4 = 0x0; var_4 <= 0x3; var_4 = var_4 + 0x1) {
            for (var_8 = 0x0; var_8 <= 0x3; var_8 = var_8 + 0x1) {
                    *(int8_t *)(sign_extend_32(var_8) + var_20 + sign_extend_64(var_4) * 0x4) = *(int8_t *)(var_18 + sign_extend_64(var_4 + var_8 * 0x4)) & 0xff;
            }
    }
    return;
}

int sub_400812(int arg0) {
    var_1 = *(int8_t *)(arg0 + 0x4) & 0xff;
    *(int8_t *)(arg0 + 0x4) = *(int8_t *)(arg0 + 0x5) & 0xff;
    *(int8_t *)(arg0 + 0x5) = *(int8_t *)(arg0 + 0x6) & 0xff;
    *(int8_t *)(arg0 + 0x6) = *(int8_t *)(arg0 + 0x7) & 0xff;
    *(int8_t *)(arg0 + 0x7) = var_1 & 0xff;
    var_1 = *(int8_t *)(arg0 + 0x8) & 0xff;
    *(int8_t *)(arg0 + 0x8) = *(int8_t *)(arg0 + 0xa) & 0xff;
    *(int8_t *)(arg0 + 0xa) = var_1 & 0xff;
    var_1 = *(int8_t *)(arg0 + 0x9) & 0xff;
    *(int8_t *)(arg0 + 0x9) = *(int8_t *)(arg0 + 0xb) & 0xff;
    *(int8_t *)(arg0 + 0xb) = var_1 & 0xff;
    var_1 = *(int8_t *)(arg0 + 0xc) & 0xff;
    *(int8_t *)(arg0 + 0xc) = *(int8_t *)(arg0 + 0xf) & 0xff;
    *(int8_t *)(arg0 + 0xf) = *(int8_t *)(arg0 + 0xe) & 0xff;
    *(int8_t *)(arg0 + 0xe) = *(int8_t *)(arg0 + 0xd) & 0xff;
    rax = var_1 & 0xff;
    *(int8_t *)(arg0 + 0xd) = rax;
    return rax;
}

void sub_400947(int arg0, int arg1) {
    round = arg0;
    some = arg1;
    for (i = 0x0; i <= 0x3; i = i + 0x1) {
            acc = 0x0;

            for (j = 0x0; j <= 0x3; j = j + 0x1) {
                    acc = acc ^ *(int32_t *)((sign_extend_32(*(int8_t *)(i + j * 4 + some)) + (i + ((round * 4) + j * 4) *256)) * 4 + 0x603060);
            }

            for (j = 0x0; j <= 0x3; j = j + 0x1) {
                    *(int8_t *)(i + j * 4) + rbp - 0x30) = acc >> j << 0x3;
            }
    }

    for (var_14 = 0x0; var_14 <= 0x3; var_14 = var_14 + 0x1) {
            for (var_18 = 0x0; var_18 <= 0x3; var_18 = var_18 + 0x1) {
                    *(int8_t *)(sign_extend_32(var_18) + sign_extend_32(var_14) * 0x4 + var_40) = *(int8_t *)(sign_extend_32(var_18) + (sign_extend_64(var_14) << 0x2) + rbp - 0x30) & 0xff;
            }
    }
    return;
}

void sub_400a7a(int arg0) {
    var_18 = arg0;
    for (var_4 = 0x0; var_4 <= 0x3; var_4 = var_4 + 0x1) {
            for (var_8 = 0x0; var_8 <= 0x3; var_8 = var_8 + 0x1) {

                    *(int8_t *)(sign_extend_32(var_8) + sign_extend_64(var_4) * 0x4 + var_18) =
                        *(int8_t *)(0x602060 + sign_extend_32(*(int8_t *)(sign_extend_32(var_8) + sign_extend_32(var_4) * 0x4 + var_18) & 0xff & 0xff) + (sign_extend_64(var_8) + (sign_extend_64(var_4) << 0x2) << 0x8)) & 0xff;
            }
    }
    return;
}

void sub_4007a5(int arg0, int arg1) {
    var_18 = arg0;
    var_20 = arg1;
    for (var_4 = 0x0; var_4 <= 0x3; var_4 = var_4 + 0x1) {
            for (var_8 = 0x0; var_8 <= 0x3; var_8 = var_8 + 0x1) {
                    *(int8_t *)(var_20 + sign_extend_64(var_4 + var_8 * 0x4)) = *(int8_t *)(sign_extend_32(var_8) + sign_extend_32(var_4) * 0x4 + var_18) & 0xff;
            }
    }
    return;
}

int printHex(int *plainText, int totalSize) {
    var_18 = arg0;
    i = 0x0;
    do {
            rax = i;
            if (rax >= totalSize) {
                break;
            }
            printf(0x400d34);
            i = i + 0x1;
    } while (true);
    return rax;
}

