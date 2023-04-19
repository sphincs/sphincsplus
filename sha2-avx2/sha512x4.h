#ifndef SHA512AVX_H
#define SHA512AVX_H
#include <stdint.h>
#include "immintrin.h"

#include "params.h"

typedef struct SHA512state4x {
    __m256i s[8];
    unsigned char msgblocks[4*128];
    int datalen;
    unsigned long long msglen;
} sha512ctx4x;


#define sha512x4_seeded SPX_NAMESPACE(sha512x4_seeded)
void sha512x4_seeded(
    unsigned char *out0,
    unsigned char *out1,
    unsigned char *out2,
    unsigned char *out3,
    const unsigned char *seed,
    unsigned long long seedlen,
    const unsigned char *in0,
    const unsigned char *in1,
    const unsigned char *in2,
    const unsigned char *in3,
    unsigned long long inlen);


/**
 * Note that inlen should be sufficiently small that it still allows for
 * an array to be allocated on the stack. Typically 'in' is merely a seed.
 * Outputs outlen number of bytes
 */
#define mgf1x4_512 SPX_NAMESPACE(mgf1x4_512)
void mgf1x4_512(unsigned char *outx4, unsigned long outlen,
            const unsigned char *in0,
            const unsigned char *in1,
            const unsigned char *in2,
            const unsigned char *in3,
            unsigned long inlen);

#endif
