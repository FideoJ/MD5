typedef MD5_CTX struct {
  uint32_t state[4];
  unsigned long long count;
};

typedef uint32_t CHUNK[16];
typedef unsigned char BYTE;

void loop(chunk ck);