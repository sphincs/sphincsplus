#ifndef SPX_FIPS202X4_H
#define SPX_FIPS202X4_H

#include <immintrin.h>

void SPX_shake128x4(unsigned char *out0,
                    unsigned char *out1,
                    unsigned char *out2,
                    unsigned char *out3,
                    unsigned long long outlen,
                    unsigned char *in0,
                    unsigned char *in1,
                    unsigned char *in2,
                    unsigned char *in3, unsigned long long inlen);

void SPX_shake256x4(unsigned char *out0,
                    unsigned char *out1,
                    unsigned char *out2,
                    unsigned char *out3,
                    unsigned long long outlen,
                    unsigned char *in0,
                    unsigned char *in1,
                    unsigned char *in2,
                    unsigned char *in3,
                    unsigned long long inlen);

#endif
