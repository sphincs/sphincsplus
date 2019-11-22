#include <string.h>

#include "sha256.h"
#include "sha256x8.h"
#include "sha256avx.h"
#include "utils.h"

void SPX_seed_statex8(sha256ctxx8 *ctx, const unsigned char *pub_seed) {
    uint8_t block[SPX_SHA256_BLOCK_BYTES];
    size_t i;

    for (i = 0; i < SPX_N; ++i) {
        block[i] = pub_seed[i];
    }
    for (i = SPX_N; i < SPX_SHA256_BLOCK_BYTES; ++i) {
        block[i] = 0;
    }

    SPX_sha256_init8x(ctx);
    SPX_sha256_update8x(ctx, block, block, block, block, block, block, block, block, SPX_SHA256_BLOCK_BYTES);

}

/* This provides a wrapper around the internals of 8x parallel SHA256 */
void SPX_sha256x8(unsigned char *out0,
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
              const unsigned char *in7, unsigned long long inlen)
{
    sha256ctxx8 ctx;
    SPX_sha256_init8x(&ctx);
    SPX_sha256_update8x(&ctx, in0, in1, in2, in3, in4, in5, in6, in7, inlen);
    SPX_sha256_final8x(&ctx, out0, out1, out2, out3, out4, out5, out6, out7);
}

/**
 * Note that inlen should be sufficiently small that it still allows for
 * an array to be allocated on the stack. Typically 'in' is merely a seed.
 * Outputs outlen number of bytes
 */
void SPX_mgf1x8(
            unsigned char *outx8,
            unsigned long outlen,
            const unsigned char *in0,
            const unsigned char *in1,
            const unsigned char *in2,
            const unsigned char *in3,
            const unsigned char *in4,
            const unsigned char *in5,
            const unsigned char *in6,
            const unsigned char *in7,
            unsigned long inlen)
{
    unsigned char inbufx8[8*((SPX_N + SPX_SHA256_ADDR_BYTES) + 4)];
    unsigned char outbufx8[8*SPX_SHA256_OUTPUT_BYTES];
    unsigned long i;
    unsigned int j;

    memcpy(inbufx8 + 0*(inlen + 4), in0, inlen);
    memcpy(inbufx8 + 1*(inlen + 4), in1, inlen);
    memcpy(inbufx8 + 2*(inlen + 4), in2, inlen);
    memcpy(inbufx8 + 3*(inlen + 4), in3, inlen);
    memcpy(inbufx8 + 4*(inlen + 4), in4, inlen);
    memcpy(inbufx8 + 5*(inlen + 4), in5, inlen);
    memcpy(inbufx8 + 6*(inlen + 4), in6, inlen);
    memcpy(inbufx8 + 7*(inlen + 4), in7, inlen);

    /* While we can fit in at least another full block of SHA256 output.. */
    for (i = 0; (i+1)*SPX_SHA256_OUTPUT_BYTES <= outlen; i++) {
        for (j = 0; j < 8; j++) {
            SPX_ull_to_bytes(inbufx8 + inlen + j*(inlen + 4), 4, i);
        }

        SPX_sha256x8(outx8 + 0*outlen,
                 outx8 + 1*outlen,
                 outx8 + 2*outlen,
                 outx8 + 3*outlen,
                 outx8 + 4*outlen,
                 outx8 + 5*outlen,
                 outx8 + 6*outlen,
                 outx8 + 7*outlen,
                 inbufx8 + 0*(inlen + 4),
                 inbufx8 + 1*(inlen + 4),
                 inbufx8 + 2*(inlen + 4),
                 inbufx8 + 3*(inlen + 4),
                 inbufx8 + 4*(inlen + 4),
                 inbufx8 + 5*(inlen + 4),
                 inbufx8 + 6*(inlen + 4),
                 inbufx8 + 7*(inlen + 4), inlen + 4);
        outx8 += SPX_SHA256_OUTPUT_BYTES;
    }
    /* Until we cannot anymore, and we fill the remainder. */
    for (j = 0; j < 8; j++) {
        SPX_ull_to_bytes(inbufx8 + inlen + j*(inlen + 4), 4, i);
    }
    SPX_sha256x8(outbufx8 + 0*SPX_SHA256_OUTPUT_BYTES,
             outbufx8 + 1*SPX_SHA256_OUTPUT_BYTES,
             outbufx8 + 2*SPX_SHA256_OUTPUT_BYTES,
             outbufx8 + 3*SPX_SHA256_OUTPUT_BYTES,
             outbufx8 + 4*SPX_SHA256_OUTPUT_BYTES,
             outbufx8 + 5*SPX_SHA256_OUTPUT_BYTES,
             outbufx8 + 6*SPX_SHA256_OUTPUT_BYTES,
             outbufx8 + 7*SPX_SHA256_OUTPUT_BYTES,
             inbufx8 + 0*(inlen + 4),
             inbufx8 + 1*(inlen + 4),
             inbufx8 + 2*(inlen + 4),
             inbufx8 + 3*(inlen + 4),
             inbufx8 + 4*(inlen + 4),
             inbufx8 + 5*(inlen + 4),
             inbufx8 + 6*(inlen + 4),
             inbufx8 + 7*(inlen + 4), inlen + 4);

    for (j = 0; j < 8; j++) {
        memcpy(outx8 + j*outlen,
               outbufx8 + j*SPX_SHA256_OUTPUT_BYTES,
               outlen - i*SPX_SHA256_OUTPUT_BYTES);
    }
}
