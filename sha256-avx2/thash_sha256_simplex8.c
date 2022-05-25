#include <stdint.h>
#include <string.h>

#include "address.h"
#include "utils.h"
#include "params.h"
#include "thashx8.h"
#include "sha256.h"
#include "sha256x8.h"
#include "sha256avx.h"
#include "sha512x4.h"

#if DO_SHA512
static void thashx4_512(unsigned char *out0,
             unsigned char *out1,
             unsigned char *out2,
             unsigned char *out3,
             const unsigned char *in0,
             const unsigned char *in1,
             const unsigned char *in2,
             const unsigned char *in3, unsigned int inblocks,
             const spx_ctx *ctx, uint32_t addrx8[4*8]);
#endif

/**
 * 8-way parallel version of thash; takes 8x as much input and output
 */
void thashx8(unsigned char *out0,
             unsigned char *out1,
             unsigned char *out2,
             unsigned char *out3,
             unsigned char *out4,
             unsigned char *out5,
             unsigned char *out6,
             unsigned char *out7,
             const unsigned char *in0,
             const unsigned char *in1,
             const unsigned char *in2,
             const unsigned char *in3,
             const unsigned char *in4,
             const unsigned char *in5,
             const unsigned char *in6,
             const unsigned char *in7, unsigned int inblocks,
             const spx_ctx *ctx, uint32_t addrx8[8*8])
{
#if DO_SHA512
    if (inblocks > 1) {
        thashx4_512(
             out0, out1, out2, out3,
             in0, in1, in2, in3,
	     inblocks, ctx, &addrx8[0]);
        thashx4_512(
             out4, out5, out6, out7,
             in4, in5, in6, in7,
	     inblocks, ctx, &addrx8[32]);
	return;
    }
#endif
    unsigned char bufx8[8*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N)];
    unsigned char outbufx8[8*SPX_SHA256_OUTPUT_BYTES];
    unsigned int i;

    for (i = 0; i < 8; i++) {
        memcpy(bufx8 + i*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
                         addrx8 + i*8, SPX_SHA256_ADDR_BYTES);
    }

    memcpy(bufx8 + SPX_SHA256_ADDR_BYTES +
        0*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N), in0, inblocks * SPX_N);
    memcpy(bufx8 + SPX_SHA256_ADDR_BYTES +
        1*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N), in1, inblocks * SPX_N);
    memcpy(bufx8 + SPX_SHA256_ADDR_BYTES +
        2*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N), in2, inblocks * SPX_N);
    memcpy(bufx8 + SPX_SHA256_ADDR_BYTES +
        3*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N), in3, inblocks * SPX_N);
    memcpy(bufx8 + SPX_SHA256_ADDR_BYTES +
        4*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N), in4, inblocks * SPX_N);
    memcpy(bufx8 + SPX_SHA256_ADDR_BYTES +
        5*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N), in5, inblocks * SPX_N);
    memcpy(bufx8 + SPX_SHA256_ADDR_BYTES +
        6*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N), in6, inblocks * SPX_N);
    memcpy(bufx8 + SPX_SHA256_ADDR_BYTES +
        7*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N), in7, inblocks * SPX_N);

    sha256x8_seeded(
        /* out */
        outbufx8 + 0*SPX_SHA256_OUTPUT_BYTES,
        outbufx8 + 1*SPX_SHA256_OUTPUT_BYTES,
        outbufx8 + 2*SPX_SHA256_OUTPUT_BYTES,
        outbufx8 + 3*SPX_SHA256_OUTPUT_BYTES,
        outbufx8 + 4*SPX_SHA256_OUTPUT_BYTES,
        outbufx8 + 5*SPX_SHA256_OUTPUT_BYTES,
        outbufx8 + 6*SPX_SHA256_OUTPUT_BYTES,
        outbufx8 + 7*SPX_SHA256_OUTPUT_BYTES,

        /* seed */
        ctx->state_seeded, 512,

        /* in */
        bufx8 + 0*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
        bufx8 + 1*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
        bufx8 + 2*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
        bufx8 + 3*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
        bufx8 + 4*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
        bufx8 + 5*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
        bufx8 + 6*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
        bufx8 + 7*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
        SPX_SHA256_ADDR_BYTES + inblocks*SPX_N /* len */
    );

    memcpy(out0, outbufx8 + 0*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out1, outbufx8 + 1*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out2, outbufx8 + 2*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out3, outbufx8 + 3*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out4, outbufx8 + 4*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out5, outbufx8 + 5*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out6, outbufx8 + 6*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out7, outbufx8 + 7*SPX_SHA256_OUTPUT_BYTES, SPX_N);
}

#if DO_SHA512
/**
 * 4-way parallel version of thash; this is for the uses of thash that are
 * based on SHA-512
 */
static void thashx4_512(unsigned char *out0,
             unsigned char *out1,
             unsigned char *out2,
             unsigned char *out3,
             const unsigned char *in0,
             const unsigned char *in1,
             const unsigned char *in2,
             const unsigned char *in3,
             unsigned int inblocks,
             const spx_ctx *ctx, uint32_t addrx8[4*8])
{
    unsigned char bufx4[4*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N)];
    __m256i outbufx4[4*SPX_SHA512_OUTPUT_BYTES / sizeof(__m256i)];
    unsigned int i;

    for (i = 0; i < 4; i++) {
        memcpy(bufx4 + i*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
                         addrx8 + i*8, SPX_SHA256_ADDR_BYTES);
    }

    memcpy(bufx4 + SPX_SHA256_ADDR_BYTES +
        0*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N), in0, inblocks * SPX_N);
    memcpy(bufx4 + SPX_SHA256_ADDR_BYTES +
        1*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N), in1, inblocks * SPX_N);
    memcpy(bufx4 + SPX_SHA256_ADDR_BYTES +
        2*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N), in2, inblocks * SPX_N);
    memcpy(bufx4 + SPX_SHA256_ADDR_BYTES +
        3*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N), in3, inblocks * SPX_N);

    sha512ctx4x hash;
    sha512_init_frombytes_x4(&hash, ctx->state_seeded_512, 512);
    sha512_update4x(&hash,  
        /* in */
        bufx4 + 0*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
        bufx4 + 1*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
        bufx4 + 2*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
        bufx4 + 3*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
        SPX_SHA256_ADDR_BYTES + inblocks*SPX_N /* len */
    );
    sha512_final4x(&hash,
        /* out */
        outbufx4 + 0*SPX_SHA512_OUTPUT_BYTES / sizeof(__m256i),
        outbufx4 + 1*SPX_SHA512_OUTPUT_BYTES / sizeof(__m256i),
        outbufx4 + 2*SPX_SHA512_OUTPUT_BYTES / sizeof(__m256i),
        outbufx4 + 3*SPX_SHA512_OUTPUT_BYTES / sizeof(__m256i)
    );

    memcpy(out0, outbufx4 + 0*SPX_SHA256_OUTPUT_BYTES / sizeof(__m256i), SPX_N);
    memcpy(out1, outbufx4 + 1*SPX_SHA256_OUTPUT_BYTES / sizeof(__m256i), SPX_N);
    memcpy(out2, outbufx4 + 2*SPX_SHA256_OUTPUT_BYTES / sizeof(__m256i), SPX_N);
    memcpy(out3, outbufx4 + 3*SPX_SHA256_OUTPUT_BYTES / sizeof(__m256i), SPX_N);
}
#endif
