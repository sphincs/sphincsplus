#include <stdint.h>
#include <string.h>

#include "address.h"
#include "utils.h"
#include "params.h"
#include "hashx8.h"
#include "sha256.h"
#include "sha256x8.h"
#include "sha256avx.h"

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
    unsigned char bufx8[8 * (SPX_N + SPX_SHA256_ADDR_BYTES)];
    unsigned char outbufx8[8 * SPX_SHA256_OUTPUT_BYTES];
    unsigned int j;

    for (j = 0; j < 8; j++) {
        memcpy(bufx8 + j*(SPX_N + SPX_SHA256_ADDR_BYTES), key, SPX_N);
        compress_address(bufx8 + SPX_N + j*(SPX_N + SPX_SHA256_ADDR_BYTES),
                         addrx8 + j*8);
    }

    sha256x8(outbufx8 + 0*SPX_SHA256_OUTPUT_BYTES,
             outbufx8 + 1*SPX_SHA256_OUTPUT_BYTES,
             outbufx8 + 2*SPX_SHA256_OUTPUT_BYTES,
             outbufx8 + 3*SPX_SHA256_OUTPUT_BYTES,
             outbufx8 + 4*SPX_SHA256_OUTPUT_BYTES,
             outbufx8 + 5*SPX_SHA256_OUTPUT_BYTES,
             outbufx8 + 6*SPX_SHA256_OUTPUT_BYTES,
             outbufx8 + 7*SPX_SHA256_OUTPUT_BYTES,
             bufx8 + 0*(SPX_N + SPX_SHA256_ADDR_BYTES),
             bufx8 + 1*(SPX_N + SPX_SHA256_ADDR_BYTES),
             bufx8 + 2*(SPX_N + SPX_SHA256_ADDR_BYTES),
             bufx8 + 3*(SPX_N + SPX_SHA256_ADDR_BYTES),
             bufx8 + 4*(SPX_N + SPX_SHA256_ADDR_BYTES),
             bufx8 + 5*(SPX_N + SPX_SHA256_ADDR_BYTES),
             bufx8 + 6*(SPX_N + SPX_SHA256_ADDR_BYTES),
             bufx8 + 7*(SPX_N + SPX_SHA256_ADDR_BYTES),
             SPX_N + SPX_SHA256_ADDR_BYTES);

    memcpy(out0, outbufx8 + 0*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out1, outbufx8 + 1*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out2, outbufx8 + 2*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out3, outbufx8 + 3*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out4, outbufx8 + 4*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out5, outbufx8 + 5*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out6, outbufx8 + 6*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out7, outbufx8 + 7*SPX_SHA256_OUTPUT_BYTES, SPX_N);
}
