void login_password(void)
{
  int iVar1;
  size_t sVar2;
  undefined8 pwd;
  undefined8 out2;
  undefined4 out3;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_18;
  
  pwd_file_name = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  local_18 = 0;
  pwd = 0;
  out2 = 0;
  out3 = 0;
  
  snprintf((char *)&pwd_file_name,0x28,"data/%s_pwd.txt",username);
  iVar1 = access((char *)&pwd_file_name,0);
  
  if (iVar1 == -1) {
    printf("creating user \'%s\' ...\nplease set your password (max-length: 19)\n",username);
    printf("password> ");
    fgets((char *)&pwd,0x14,stdin);
    sVar2 = strcspn((char *)&pwd,"\n");
    *(undefined *)((long)&pwd + sVar2) = 0;
    create_user(&pwd_file_name,&pwd,&out1);
  }
  else {
    printf("found user \'%s\' ...\n",username);
    while( true ) {
      printf("password> ");
      fgets((char *)&pwd,0x14,stdin);
      sVar2 = strcspn((char *)&pwd,"\n");
      *(undefined *)((long)&pwd + sVar2) = 0;
      iVar1 = check_pwd(&pwd_file_name,&pwd,&out1);
      if (iVar1 != 0) break;
      puts("wrong password!");
    }
  }
  printf("welcome %s!\n",username);
  return;
}


void create_user(char *pwd_file_name,char *pwd)
{
  size_t sVar1;
  FILE *__s;

  sVar1 = strlen(pwd);
  calc_hash(pwd,sVar1,pwd_hash,sVar1);
  __s = fopen(pwd_file_name,"w");
  fwrite(pwd_hash,1,0x10,__s);
  fclose(__s);
  return;
}


void calc_hash(long pwd, ulong pwd_len, ulong *hash_out)
{
  char ch;
  ulong out1;
  ulong out2;
  ulong out3;
  ulong out4;
  int i;
  ulong local_28;
  ulong local_20;
  ulong local_18;
  ulong local_10;

  out1 = 0x68736168;
  out2 = 0xdeadbeef;
  out3 = 0x65726f6d;
  out4 = 0xc00ffeee;
  local_10 = 0x68736168;
  local_18 = 0xdeadbeef;
  local_20 = 0x65726f6d;


  i = 0;
  while (i < pwd_len) {
    ch = *(char *)(pwd + i);
    
    out2 = local_10 ^
               (long)(int)(ch * i & 0xffU ^ (int)ch |
                          ((int)ch * (i + 0x31) & 0xffU ^ (int)ch) << 0x18 |
                          ((int)ch * (i + 0x42) & 0xffU ^ (int)ch) << 0x10 |
                          ((int)ch * (i + 0xef) & 0xffU ^ (int)ch) << 8);

    out3 = local_18 ^
               (long)(int)(ch * i & 0x5aU ^ (int)ch |
                          ((int)ch * (i + 0xc0) & 0xffU ^ (int)ch) << 0x18 |
                          ((int)ch * (i + 0x11) & 0xffU ^ (int)ch) << 0x10 |
                          ((int)ch * (i + 0xde) & 0xffU ^ (int)ch) << 8);

    out4 = local_20 ^
               (long)(int)(ch * i & 0x22U ^ (int)ch |
                          ((int)ch * (i + 0xe3) & 0xffU ^ (int)ch) << 0x18 |
                          ((int)ch * (i + 0xde) & 0xffU ^ (int)ch) << 0x10 |
                          ((int)ch * (i + 0xd) & 0xffU ^ (int)ch) << 8);

    out1 = local_28 ^
               (long)(int)(ch * i & 0xefU ^ (int)ch |
                          ((int)ch * (i + 0x52) & 0xffU ^ (int)ch) << 0x18 |
                          ((int)ch * (i + 0x24) & 0xffU ^ (int)ch) << 0x10 |
                          ((int)ch * (i + 0x33) & 0xffU ^ (int)ch) << 8);
    i = i + 1;
    local_28 = out1;
    local_20 = out4;
    local_18 = out3;
    local_10 = out2;
  }
  
  *hash_out = out1;
  *(ulong *)((long)hash_out + 4) = out2;
  hash_out[1] = out3;
  *(ulong *)((long)hash_out + 0xc) = out4;
  return; // 16 bytes hash --> 128 bits
}


bool check_pwd(char *pwd_file_name,char *pwd)
{
  int cmp_result;
  size_t pwd_len;
  bool result;
  undefined8 hash_out;
  undefined8 local_20;
  size_t pwd_hash_len;
  FILE *pwd_file;

  pwd_file = fopen(pwd_file_name,"r");
  pwd_hash_len = fread(pwd_hash,1,0x10,pwd_file);
  fclose(pwd_file);
  if (pwd_hash_len == 0x10) {
    hash_out = 0;
    local_20 = 0;
    pwd_len = strlen(pwd);
    calc_hash(pwd,pwd_len,&hash_out/*,pwd_len*/);
    cmp_result = memcmp(pwd_hash,&hash_out,0x10);
    result = (cmp_result == 0);
  }
  else {
    result = false;
  }
  return result;
}


void show_menu(void)
{
  char choice [10];
  char data_file_name [44];
  int choice_num;
  
  snprintf(data_file_name,0x28,"data/%s_data.txt",username);
  while( true ) {
    while( true ) {
      while( true ) {
        while( true ) {
          puts("[0] show data");
          puts("[1] enter data");
          puts("[2] delete data");
          puts("[3] quit");
          printf("choice> ");
          fgets(choice,1000,stdin); // 1000 !!!
          choice_num = atoi(choice);
          if (choice_num != 0) break;
          show_data(data_file_name);
        }
        if (choice_num != 1) break;
        enter_data(data_file_name);
      }
      if (choice_num != 2) break;
      delete_data(data_file_name);
    }
    if (choice_num == 3) break;
    puts("unknown choice!");
  }
  puts("good bye!");
  return;
}


void show_data(char *data_file_name)
{
  int iVar1;
  FILE *__stream;
  size_t *outlen;
  size_t in_R8;
  EVP_PKEY_CTX data [104];
  FILE *local_10;

  iVar1 = access(data_file_name,0);
  if (iVar1 == -1) {
    puts("no data found!");
  }
  else {
    memset(data,0,100);
    __stream = fopen(data_file_name,"r");
    local_10 = __stream;
    fread(data,1,100,__stream);
    fclose(local_10);
    decrypt(data,pwd_hash,outlen,(uchar *)__stream,in_R8);
    printf("your secret data:\n%s\n",data);
  }
  return;
}


void encrypt(char *__block,int __edflag)
{
  byte key_byte;
  int i;

  i = 0;
  while (__block[i] != '\0') {
    key_byte = keystream_get_char(i);
    __block[i] = key_byte ^ __block[i];
    i = i + 1;
  }
  key_byte = keystream_get_char(i); // encrypt null byte
  __block[i] = key_byte ^ __block[i];
  return;
}


int decrypt(EVP_PKEY_CTX *ctx,uchar *out,size_t *outlen,uchar *in,size_t inlen)
{
  byte key_byte;
  int i;
  
  i = 0;
  while( true ) {
    key_byte = keystream_get_char(i);
    ctx[i] = (EVP_PKEY_CTX)(key_byte ^ (byte)ctx[i]);
    if (ctx[i] == (EVP_PKEY_CTX)0x0) break;
    i = i + 1;
  }
  return 0;
}


// Ghidra
long keystream_get_char(uint i, long pwd_hash)
{
  uint uVar1;
  undefined8 magic1;
  undefined2 local_1a;
  char local_9;

  magic1 = 0x563412c0efbeadde;
  local_1a = 0x9a78;
  
  uVar1 = (uint)((int)i >> 0x1f) >> 0x1c;
  local_9 = *(char *)(pwd_hash + (int)((i + uVar1 & 0xf) - uVar1));
  return (long)(int)((int)*(char *)((long)&magic1 + (ulong)(long)local_9 % 10) ^
                    (int)local_9 ^ i);
}


// Hopper v4
int keystream_get_char(int i, int pwd_hash) {
    rax = *(int8_t *)(pwd_hash + sign_extend_64((i + ((i & 0x80000000 ? 0xffffffff : 0x0) >> 0x1c) & 0xf) - ((i & 0x80000000 ? 0xffffffff : 0x0) >> 0x1c))) & 0xff;
    rsi = sign_extend_64(rax) ^ i;
    rax = *(int8_t *)(rbp + (sign_extend_64(rax) - (HIQWORD(sign_extend_64(rax) * 0xcccccccccccccccd) >> 0x3 << 0x2) + (HIQWORD(sign_extend_64(rax) * 0xcccccccccccccccd) >> 0x3) + (HIQWORD(sign_extend_64(rax) * 0xcccccccccccccccd) >> 0x3 << 0x2) + (HIQWORD(sign_extend_64(rax) * 0xcccccccccccccccd) >> 0x3) - 0x1a)) & 0xff;
    rax = sign_extend_32(sign_extend_64(rax) ^ rsi);
    return rax;
}
