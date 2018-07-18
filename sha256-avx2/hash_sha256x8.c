#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>

#include "hash_address.h"
#include "utils.h"
#include "params.h"
#include "hash.h"
#include "sha256avx.h"

#define SPX_SHA256_OUTPUT_BYTES 32  /* This does not necessarily equal SPX_N */

#if SPX_SHA256_OUTPUT_BYTES < SPX_N
    #error Linking against SHA-256 with N larger than 32 bytes is not supported
#endif

/* This provides a wrapper around the internals of 8x parallel SHA256 */
static void sha256x8(unsigned char *out0,
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
    sha256ctx ctx;
    sha256_init8x(&ctx);
    sha256_update8x(&ctx, in0, in1, in2, in3, in4, in5, in6, in7, inlen);
    sha256_final8x(&ctx, out0, out1, out2, out3, out4, out5, out6, out7);
}

static void addr_to_bytes(unsigned char *bytes, const uint32_t addr[8])
{
    int i;

    for (i = 0; i < 8; i++) {
        ull_to_bytes(bytes + i*4, 4, addr[i]);
    }
}

/**
 * Note that inlen should be sufficiently small that it still allows for
 * an array to be allocated on the stack. Typically 'in' is merely a seed.
 * Outputs outlen number of bytes
 */
static void mgf1x8(unsigned char *outx8, unsigned long outlen,
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
    unsigned char inbufx8[8*(inlen + 4)];
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
            ull_to_bytes(inbufx8 + inlen + j*(inlen + 4), 4, i);
        }

        sha256x8(outx8 + 0*outlen,
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
        ull_to_bytes(inbufx8 + inlen + j*(inlen + 4), 4, i);
    }
    sha256x8(outbufx8 + 0*SPX_SHA256_OUTPUT_BYTES,
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

/*
 * 8-way parallel version of prf_addr; takes 8x as much input and output
 */
void prf_addrx8(unsigned char *out0,
                unsigned char *out1,
                unsigned char *out2,
                unsigned char *out3,
                unsigned char *out4,
                unsigned char *out5,
                unsigned char *out6,
                unsigned char *out7,
                const unsigned char *key,
                const uint32_t addrx8[8*8])
{
    unsigned char bufx8[8 * (SPX_N + SPX_ADDR_BYTES)];
    unsigned char outbufx8[8 * SPX_SHA256_OUTPUT_BYTES];
    unsigned int j;

    for (j = 0; j < 8; j++) {
        memcpy(bufx8 + j*(SPX_N + SPX_ADDR_BYTES), key, SPX_N);
        addr_to_bytes(bufx8 + SPX_N + j*(SPX_N + SPX_ADDR_BYTES), addrx8 + j*8);
    }

    sha256x8(outbufx8 + 0*SPX_SHA256_OUTPUT_BYTES,
             outbufx8 + 1*SPX_SHA256_OUTPUT_BYTES,
             outbufx8 + 2*SPX_SHA256_OUTPUT_BYTES,
             outbufx8 + 3*SPX_SHA256_OUTPUT_BYTES,
             outbufx8 + 4*SPX_SHA256_OUTPUT_BYTES,
             outbufx8 + 5*SPX_SHA256_OUTPUT_BYTES,
             outbufx8 + 6*SPX_SHA256_OUTPUT_BYTES,
             outbufx8 + 7*SPX_SHA256_OUTPUT_BYTES,
             bufx8 + 0*(SPX_N + SPX_ADDR_BYTES),
             bufx8 + 1*(SPX_N + SPX_ADDR_BYTES),
             bufx8 + 2*(SPX_N + SPX_ADDR_BYTES),
             bufx8 + 3*(SPX_N + SPX_ADDR_BYTES),
             bufx8 + 4*(SPX_N + SPX_ADDR_BYTES),
             bufx8 + 5*(SPX_N + SPX_ADDR_BYTES),
             bufx8 + 6*(SPX_N + SPX_ADDR_BYTES),
             bufx8 + 7*(SPX_N + SPX_ADDR_BYTES),
             SPX_N + SPX_ADDR_BYTES);

    memcpy(out0, outbufx8 + 0*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out1, outbufx8 + 1*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out2, outbufx8 + 2*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out3, outbufx8 + 3*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out4, outbufx8 + 4*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out5, outbufx8 + 5*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out6, outbufx8 + 6*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out7, outbufx8 + 7*SPX_SHA256_OUTPUT_BYTES, SPX_N);
}

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
             const unsigned char *pub_seed, uint32_t addrx8[8*8])
{
    unsigned char bufx8[8*(SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N)];
    unsigned char outbufx8[8*SPX_SHA256_OUTPUT_BYTES];
    unsigned char bitmaskx8[8*(inblocks * SPX_N)];
    unsigned int i, j;

    memset(bufx8, 0, 8*(SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N));

    for (j = 0; j < 8; j++) {
        memcpy(bufx8 + j*(SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N), pub_seed, SPX_N);
        addr_to_bytes(bufx8 + SPX_N + j*(SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N), addrx8 + j*8);
    }

    mgf1x8(bitmaskx8, inblocks * SPX_N,
           bufx8 + 0*(SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N),
           bufx8 + 1*(SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N),
           bufx8 + 2*(SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N),
           bufx8 + 3*(SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N),
           bufx8 + 4*(SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N),
           bufx8 + 5*(SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N),
           bufx8 + 6*(SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N),
           bufx8 + 7*(SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N),
           SPX_N + SPX_ADDR_BYTES);

    for (i = 0; i < inblocks * SPX_N; i++) {
        bufx8[SPX_N + SPX_ADDR_BYTES + i +
                0*(SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N)] =
            in0[i] ^ bitmaskx8[i + 0*(inblocks * SPX_N)];
        bufx8[SPX_N + SPX_ADDR_BYTES + i +
                1*(SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N)] =
            in1[i] ^ bitmaskx8[i + 1*(inblocks * SPX_N)];
        bufx8[SPX_N + SPX_ADDR_BYTES + i +
                2*(SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N)] =
            in2[i] ^ bitmaskx8[i + 2*(inblocks * SPX_N)];
        bufx8[SPX_N + SPX_ADDR_BYTES + i +
                3*(SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N)] =
            in3[i] ^ bitmaskx8[i + 3*(inblocks * SPX_N)];
        bufx8[SPX_N + SPX_ADDR_BYTES + i +
                4*(SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N)] =
            in4[i] ^ bitmaskx8[i + 4*(inblocks * SPX_N)];
        bufx8[SPX_N + SPX_ADDR_BYTES + i +
                5*(SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N)] =
            in5[i] ^ bitmaskx8[i + 5*(inblocks * SPX_N)];
        bufx8[SPX_N + SPX_ADDR_BYTES + i +
                6*(SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N)] =
            in6[i] ^ bitmaskx8[i + 6*(inblocks * SPX_N)];
        bufx8[SPX_N + SPX_ADDR_BYTES + i +
                7*(SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N)] =
            in7[i] ^ bitmaskx8[i + 7*(inblocks * SPX_N)];
    }

    sha256x8(outbufx8 + 0*SPX_SHA256_OUTPUT_BYTES,
             outbufx8 + 1*SPX_SHA256_OUTPUT_BYTES,
             outbufx8 + 2*SPX_SHA256_OUTPUT_BYTES,
             outbufx8 + 3*SPX_SHA256_OUTPUT_BYTES,
             outbufx8 + 4*SPX_SHA256_OUTPUT_BYTES,
             outbufx8 + 5*SPX_SHA256_OUTPUT_BYTES,
             outbufx8 + 6*SPX_SHA256_OUTPUT_BYTES,
             outbufx8 + 7*SPX_SHA256_OUTPUT_BYTES,
             bufx8 + 0*(SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N),
             bufx8 + 1*(SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N),
             bufx8 + 2*(SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N),
             bufx8 + 3*(SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N),
             bufx8 + 4*(SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N),
             bufx8 + 5*(SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N),
             bufx8 + 6*(SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N),
             bufx8 + 7*(SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N),
             SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N);

    memcpy(out0, outbufx8 + 0*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out1, outbufx8 + 1*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out2, outbufx8 + 2*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out3, outbufx8 + 3*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out4, outbufx8 + 4*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out5, outbufx8 + 5*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out6, outbufx8 + 6*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out7, outbufx8 + 7*SPX_SHA256_OUTPUT_BYTES, SPX_N);
}
