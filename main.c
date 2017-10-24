int main() {
  init_k();
  md5_driver("message digest");
  return 0;
}

void md5_print(Byte digest[16]) {
  unsigned int i;

  for (i = 0; i < 16; ++i)
    printf("%02x", digest[i]);
}

void md5_driver(char *string) {
  MD5_CTX context;
  Byte digest[16];
  unsigned int len = strlen(string);

  md5_init(&context);
  md5_update(&context, string, len);
  md5_final(digest, &context);

  printf("MD5 (\"%s\") = ", string);
  md5_print(digest);
  printf("\n");
}