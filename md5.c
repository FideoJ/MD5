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

// 进行md5计算前需调用且只需调用一次，多次调用不会影响正确性
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

// input为消息的一部分或全部。input_len为此次输入的长度，以【字节】为单位，为32位整数
void md5_update(MD5_CTX *context, Byte *input, uint32_t input_len) {
  // unconsumed表示上一次未能凑整512比特而留下来的未哈希的【字节】数
  unsigned int i, unconsumed;

  unconsumed = (unsigned int)((context->count[0] >> 3) % 64);

  // 溢出则进位，需注意比特与字节的单位转换
  if ((context->count[0] += input_len << 3) < input_len << 3)
    context->count[1]++;
  context->count[1] += ((uint32_t)input_len >> 29);

  // 若此次输入与之前剩余的字节能够凑足至少一个Block（512bit）
  if (unconsumed + input_len >= 64) {
    // 把之前剩余的不足一个block补足并哈希
    md5_memcpy(context->buffer + unconsumed, input, 64 - unconsumed);
    md5_transform(context->state, context->buffer);

    // 对剩下的输入不断分块并哈希直至无法再凑整一个块
    // 当前分块区间（以字节为单位）：input[i, i+64)
    for (i = 64 - unconsumed; i + 64 <= input_len; i += 64)
      // 无需先复制进buffer
      md5_transform(context->state, input + i);

    // 将此次输入剩余的不足一个block的部分复制进buffer，留待下次处理
    md5_memcpy(context->buffer, input + i, input_len - i);
  } else {
    // 此次输入与之前剩余的字节无法凑足至少一个Block（512bit）
    // 将此次输入添加到原buffer尾部，留待下次处理
    md5_memcpy(context->buffer + unconsumed, input, input_len);
  }
}

// 表示消息已结束，需处理PADDING并输出整个消息的摘要
void md5_final(Byte digest[16], MD5_CTX *context) {
  Byte total_len[8];
  unsigned int unconsumed, padding_len;

  // 将消息长度编码为字节（小端表示）
  encode(total_len, context->count, 8);

  unconsumed = (unsigned int)((context->count[0] >> 3) % 64);
  // 补足1或2个Block
  padding_len = (unconsumed < 56) ? (56 - unconsumed) : (56 + 64 - unconsumed);
  // 将PADDING作为输入进行update，会剩余一部分于buffer中
  // 此时count的更新已无意义
  md5_update(context, PADDING, padding_len);

  // 加入编码好的消息长度，完成最后一次update，此时buffer中不再剩余
  md5_update(context, total_len, 8);

  // 将消息摘要编码为字节（小端表示）
  encode(digest, context->state, 16);

  // 清空context，留作下次md5计算使用
  md5_clear(context, sizeof(*context));
}

// 接收字节表示的Block以更新传入的state
void md5_transform(uint32_t state[4], Byte block[64]) {
  Block bk;
  // 解码Block为16个32比特无符号整数
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

    // 计算并轮转
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

// 将以若干个32比特无符号整数表示的输入编码为字节表示的输出（小端法），output_len需为4的倍数，以字节为单位
void encode(Byte *output, uint32_t *input, unsigned int output_len) {
  unsigned int i, j;

  for (i = 0, j = 0; j < output_len; ++i, j += 4) {
    output[j] = (Byte)(input[i] & 0xff);
    output[j + 1] = (Byte)((input[i] >> 8) & 0xff);
    output[j + 2] = (Byte)((input[i] >> 16) & 0xff);
    output[j + 3] = (Byte)((input[i] >> 24) & 0xff);
  }
}

// 将字节表示的输入（长度为4的倍数）解码为以若干个32比特无符号整数表示的输出
void decode(uint32_t *output, Byte *input, unsigned int output_len) {
  unsigned int i, j;

  for (i = 0, j = 0; j < output_len; i += 4, ++j)
    output[j] = ((uint32_t)input[i]) | (((uint32_t)input[i + 1]) << 8) |
                (((uint32_t)input[i + 2]) << 16) |
                (((uint32_t)input[i + 3]) << 24);
}

// 左循环移位
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
