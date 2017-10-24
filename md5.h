#include <stdint.h>

typedef uint32_t Block[16];
typedef unsigned char Byte;

typedef struct MD5Context {
  uint32_t state[4];
  uint32_t count[2]; //  以比特为单位
  Byte buffer[64];   //  存放未能凑成一个block的未哈希字节
} MD5_CTX;

void init_T_TABLE();
void md5_init(MD5_CTX *context);
void md5_update(MD5_CTX *context, Byte *input, uint32_t input_len);
void md5_final(Byte digest[16], MD5_CTX *context);
void md5_transform(uint32_t state[4], Byte block[64]);
void consume(uint32_t state[4], Block bk);

void encode(Byte *output, uint32_t *input, unsigned int output_len);
void decode(uint32_t *output, Byte *input, unsigned int output_len);
uint32_t left_rotate(uint32_t w, int shift);
void md5_memcpy(Byte *output, Byte *input, unsigned int len);
void md5_clear(MD5_CTX *context, unsigned int len);
