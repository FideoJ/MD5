#include "md5.h"
#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

int r[64] = {7,  12, 17, 22, 7,  12, 17, 22, 7,  12, 17, 22, 7,  12, 17, 22,
             5,  9,  14, 20, 5,  9,  14, 20, 5,  9,  14, 20, 5,  9,  14, 20,
             4,  11, 16, 23, 4,  11, 16, 23, 4,  11, 16, 23, 4,  11, 16, 6,
             10, 15, 21, 6,  10, 15, 21, 6,  10, 15, 21, 6,  10, 15, 21};
uint32_t k[64];
uint32_t h0, h1, h2, h3;

void init();
void md5(BYTE *message, BYTE end, BYTE digest[16]);
void process_chunk(BYTE *start);
void encode(BYTE *output);
void decode(BYTE *input, CHUNK output);
void consume(CHUNK ck);
uint32_t left_rotate(uint32_t w, int shift);

void MD5Init(MD5_CTX *context) {
  context->count = 0ULL;

  context->state[0] = 0x67452301;
  context->state[1] = 0xefcdab89;
  context->state[2] = 0x98badcfe;
  context->state[3] = 0x10325476;
}

void init() {
  int i;
  for (i = 0; i < 64; ++i)
    k[i] = (uint32_t)floor(fabs(sin(i + 1)) * pow(2.0, 32.0));
}

void md5(BYTE *message, BYTE end, BYTE digest[16]) {
  init();

  unsigned long long cur = 0;
  bool first = true;

  while (message[cur] != end) {
    if (cur == 0) {
      if (first) {
        first = false;
      } else {
        message += ULLONG_MAX;
        message += 1;
      }
    }
    if (cur % 512 == 0) {
      process_chunk(message + cur);
    }
    ++cur;
  }

  encode(digest);
  // CHUNK padding[2];
  // padding
}

void process_chunk(BYTE *start) {
  CHUNK ck;
  decode(start, ck);
  consume(ck);
}

void encode(BYTE *output) {
  uint32_t h[4] = {h0, h1, h2, h3};
  int i;
  for (i = 0; i < 4; ++i) {
    output[i * 4] = (BYTE)(h[i] & 0xff);
    output[i * 4 + 1] = (BYTE)((h[i] >> 8) & 0xff);
    output[i * 4 + 2] = (BYTE)((h[i] >> 16) & 0xff);
    output[i * 4 + 3] = (BYTE)((h[i] >> 24) & 0xff);
  }
}

void decode(BYTE *input, CHUNK output) {
  int i, j;
  for (i = 0; i < 16; ++i) {
    j = 4 * i;
    output[i] = (((uint32_t)input[j])) | (((uint32_t)input[j + 1]) << 8) |
                (((uint32_t)input[j + 2]) << 16) |
                (((uint32_t)input[j + 3]) << 24);
  }
}

void consume(CHUNK ck) {
  uint32_t a = h0;
  uint32_t b = h1;
  uint32_t c = h2;
  uint32_t d = h3;
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
    b = left_rotate((a + f + k[i] + ck[g]), r[i]) + b;
    a = temp;
  }

  h0 = h0 + a;
  h1 = h1 + b;
  h2 = h2 + c;
  h3 = h3 + d;
}

uint32_t left_rotate(uint32_t w, int shift) {
  shift = shift % 32;
  return (w << shift) | (w >> (32 - shift));
}

int main() {
  BYTE message[65];
  BYTE digest[16];
  int i;
  for (i = 0; i < 64; ++i)
    message[i] = 4 * (i + 1);
  message[64] = 0;
  md5(message, 0, digest);
  for (i = 0; i < 16; ++i)
    printf("%02x", digest[i]);
  printf("\n");
  return 0;
}