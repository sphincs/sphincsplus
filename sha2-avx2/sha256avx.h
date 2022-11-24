#ifndef SHA256AVX_H
#define SHA256AVX_H

#include <stdint.h>
#include <immintrin.h>

typedef struct SHA256state {
    __m256i s[8];
    unsigned char msgblocks[8*64];
    int datalen;
    unsigned long long msglen;
} sha256x8ctx;

void sha256_ctx_clone8x(sha256x8ctx *out, const sha256x8ctx *in);
void sha256_init8x(sha256x8ctx *ctx);
void sha256_final8x(sha256x8ctx *ctx,
                    unsigned char *out0,
                    unsigned char *out1,
                    unsigned char *out2,
                    unsigned char *out3,
                    unsigned char *out4,
                    unsigned char *out5,
                    unsigned char *out6,
                    unsigned char *out7);

void sha256_transform8x(sha256x8ctx *ctx,
        const unsigned char *data0,
        const unsigned char *data1,
        const unsigned char *data2,
        const unsigned char *data3,
        const unsigned char *data4,
        const unsigned char *data5,
        const unsigned char *data6,
        const unsigned char *data7);

#endif
