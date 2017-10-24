#include "md5.h"
#include <stdio.h>
#include <string.h>

void md5_test(char *message, char *expected);
void digest2str(Byte digest[16], char dstr[33]);

MD5_CTX context;

int main() {
  init_T_TABLE();
  md5_test("", "d41d8cd98f00b204e9800998ecf8427e");
  md5_test("a", "0cc175b9c0f1b6a831c399e269772661");
  md5_test("abc", "900150983cd24fb0d6963f7d28e17f72");
  md5_test("message digest", "f96b697d7cb7938d525a2f31aaf161d0");
  md5_test("abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b");
  md5_test("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
           "d174ab98d277d9f5a5611c2c9f419d9f");
  md5_test("1234567890123456789012345678901234567890123456789012345678901234567"
           "8901234567890",
           "57edf4a22be3c955ac49da2e2107b67a");
  return 0;
}

void md5_test(char *message, char *expected) {
  Byte digest[16];

  md5_init(&context);
  md5_update(&context, (Byte *)message, (uint32_t)strlen(message));
  md5_final(digest, &context);

  char dstr[33];
  digest2str(digest, dstr);

  printf("MESSAGE: \"%s\"\n", message);
  printf("EXPECTED: \"%s\"\n", expected);
  printf("COMPUTED: \"%s\"\n", dstr);
  printf("RESULT: %s\n\n", strncmp(expected, dstr, 33) ? "FAIL" : "PASS");
}

// 将字节表示的消息摘要转换为字符串
void digest2str(Byte digest[16], char dstr[33]) {
  unsigned int i;

  for (i = 0; i < 16; ++i)
    snprintf(dstr + i * 2, 3, "%02x", digest[i]);
}
