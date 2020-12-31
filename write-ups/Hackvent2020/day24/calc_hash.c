#include <stdio.h>
#include <string.h>

// Read password list line by line, calc hash, save it into hashes.bin (16 bytes per hash).

int main()
{
    char ch;
    unsigned int out1;
    unsigned int out2;
    unsigned int out3;
    unsigned int out4;
    int i;
    unsigned int local_28;
    unsigned int local_20;
    unsigned int local_18;
    unsigned int local_10;

    FILE *fp_out;
    fp_out = fopen("hashes.bin", "w+");

    FILE *fp_in;
    char *line = NULL;
    size_t len = 0;
    size_t read;

    fp_in = fopen("rockyou.txt", "r");

    while ((read = getline(&line, &len, fp_in)) != -1) {
        //printf("%s", line);

        out1 = 0x68736168;
        out2 = 0xdeadbeef;
        out3 = 0x65726f6d;
        out4 = 0xc00ffeee;
        local_10 = 0x68736168;
        local_18 = 0xdeadbeef;
        local_20 = 0x65726f6d;
        local_28 = 0xc00ffeee;

        i = 0;
        while ( 1 ) {
            ch = *(char *)(line + i);
            if (ch == 0xa) break;

            out2 = local_10 ^
                    (ch * i & 0xffU ^ ch |
                               (ch * (i + 0x31) & 0xffU ^ ch) << 0x18 |
                               (ch * (i + 0x42) & 0xffU ^ ch) << 0x10 |
                               (ch * (i + 0xef) & 0xffU ^ ch) << 8);
            out3 = local_18 ^
                    (ch * i & 0x5aU ^ ch |
                               (ch * (i + 0xc0) & 0xffU ^ ch) << 0x18 |
                               (ch * (i + 0x11) & 0xffU ^ ch) << 0x10 |
                               (ch * (i + 0xde) & 0xffU ^ ch) << 8);
            out4 = local_20 ^
                    (ch * i & 0x22U ^ ch |
                               (ch * (i + 0xe3) & 0xffU ^ ch) << 0x18 |
                               (ch * (i + 0xde) & 0xffU ^ ch) << 0x10 |
                               (ch * (i + 0xd) & 0xffU ^ ch) << 8);
            out1 = local_28 ^
                    (ch * i & 0xefU ^ ch |
                               (ch * (i + 0x52) & 0xffU ^ ch) << 0x18 |
                               (ch * (i + 0x24) & 0xffU ^ ch) << 0x10 |
                               (ch * (i + 0x33) & 0xffU ^ ch) << 8);
            i = i + 1;
            local_28 = out1;
            local_20 = out4;
            local_18 = out3;
            local_10 = out2;
        }

        fwrite(&out1, sizeof out1, 1, fp_out);
        fwrite(&out2, sizeof out2, 1, fp_out);
        fwrite(&out3, sizeof out3, 1, fp_out);
        fwrite(&out4, sizeof out4, 1, fp_out);
   }

    fclose(fp_in);
    fclose(fp_out);

    return 0;
}
