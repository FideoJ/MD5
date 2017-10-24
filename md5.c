#include "md5.h"
#include <math.h>
#include <stdint.h>

int LR_OFFSET[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
};

Byte PADDING[64] = {0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
uint32_t T_TABLE[64];

void init_T_TABLE() {
  unsigned int i;
  for (i = 0; i < 64; ++i)
    T_TABLE[i] = (uint32_t)floor(fabs(sin(i + 1)) * pow(2.0, 32.0));
}

void md5_init(MD5_CTX *context) {
  // count以比特为单位
  context->count[0] = context->count[1] = 0;

  context->state[0] = 0x67452301;
  context->state[1] = 0xefcdab89;
  context->state[2] = 0x98badcfe;
  context->state[3] = 0x10325476;
}

// input_len以【字节】为单位，为32位整数
void md5_update(MD5_CTX *context, Byte *input, uint32_t input_len) {
  // unconsumed表示上一次未能凑整512比特而留下来的未哈希的【字节】数
  unsigned int i, unconsumed;

  unconsumed = (unsigned int)((context->count[0] >> 3) % 64);

  if ((context->count[0] += input_len << 3) < input_len << 3) /* overflow */
    context->count[1]++;
  context->count[1] += ((uint32_t)input_len >> 29);

  /* Transform as many times as possible.*/
  if (unconsumed + input_len >= 64) {
    // 把之前不足一个block的补足，特殊情况unconsumed=0
    md5_memcpy(context->buffer + unconsumed, input, 64 - unconsumed);
    md5_transform(context->state, context->buffer);

    // i为区间左端点（包括）
    // i + 64为区间右端点（未包括）
    for (i = 64 - unconsumed; i + 64 <= input_len; i += 64)
      // 无需先cp进buffer
      md5_transform(context->state, input + i);

    // 剩余不足一个block的cp进buf
    md5_memcpy(context->buffer, input + i, input_len - i);
  } else {
    md5_memcpy(context->buffer + unconsumed, input, input_len);
  }
}

void md5_final(Byte digest[16], MD5_CTX *context) {
  Byte total_len[8];
  unsigned int unconsumed, padding_len;

  /* Save number of bits */
  encode(total_len, context->count, 8);

  /* Pad out to 56 mod 64.
*/
  unconsumed = (unsigned int)((context->count[0] >> 3) & 0x3f);
  padding_len = (unconsumed < 56) ? (56 - unconsumed) : (56 + 64 - unconsumed);
  md5_update(context, PADDING, padding_len);

  /* Append length (before padding) */
  md5_update(context, total_len, 8);

  /* Store state in digest */
  encode(digest, context->state, 16);

  md5_clear(context, sizeof(*context));
}

void md5_transform(uint32_t state[4], Byte block[64]) {
  Block bk;
  decode(bk, block, 16);
  consume(state, bk);
}

void consume(uint32_t state[4], Block bk) {
  uint32_t a = state[0];
  uint32_t b = state[1];
  uint32_t c = state[2];
  uint32_t d = state[3];
  uint32_t f, temp;
  int i, g;

  for (i = 0; i < 64; ++i) {
    switch (i / 16) {
    case 0:
      f = (b & c) | (~b & d);
      g = i;
      break;
    case 1:
      f = (d & b) | (~d & c);
      g = (5 * i + 1) % 16;
      break;
    case 2:
      f = b ^ c ^ d;
      g = (3 * i + 5) % 16;
      break;
    case 3:
      f = c ^ (b | ~d);
      g = (7 * i) % 16;
      break;
    }

    temp = d;
    d = c;
    c = b;
    b = left_rotate((a + f + T_TABLE[i] + bk[g]), LR_OFFSET[i]) + b;
    a = temp;
  }

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
}

void encode(Byte *output, uint32_t *input, unsigned int output_len) {
  unsigned int i, j;

  for (i = 0, j = 0; j < output_len; ++i, j += 4) {
    output[j] = (Byte)(input[i] & 0xff);
    output[j + 1] = (Byte)((input[i] >> 8) & 0xff);
    output[j + 2] = (Byte)((input[i] >> 16) & 0xff);
    output[j + 3] = (Byte)((input[i] >> 24) & 0xff);
  }
}

void decode(uint32_t *output, Byte *input, unsigned int output_len) {
  unsigned int i, j;

  for (i = 0, j = 0; j < output_len; i += 4, ++j)
    output[j] = ((uint32_t)input[i]) | (((uint32_t)input[i + 1]) << 8) |
                (((uint32_t)input[i + 2]) << 16) |
                (((uint32_t)input[i + 3]) << 24);
}

uint32_t left_rotate(uint32_t w, int shift) {
  shift = shift % 32;
  return (w << shift) | (w >> (32 - shift));
}

void md5_memcpy(Byte *output, Byte *input, unsigned int len) {
  unsigned int i;
  for (i = 0; i < len; i++)
    output[i] = input[i];
}

void md5_clear(MD5_CTX *context, unsigned int len) {
  unsigned int i;
  for (i = 0; i < len; i++)
    ((char *)context)[i] = (char)0;
}
