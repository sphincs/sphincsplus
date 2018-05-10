#include <stdint.h>
#include <string.h>

#include "utils.h"
#include "params.h"
#include "hashx4.h"
#include "haraka.h"
#include "harakax4.h"

static void addr_to_bytes(unsigned char *bytes, const uint32_t addr[8])
{
    int i;

    for (i = 0; i < 8; i++) {
        ull_to_bytes(bytes + i*4, 4, addr[i]);
    }
}

/*
 * 4-way parallel version of prf_addr; takes 4x as much input and output
 */
void prf_addrx4(unsigned char *out0,
                unsigned char *out1,
                unsigned char *out2,
                unsigned char *out3,
                const unsigned char *key,
                const uint32_t addrx4[4*8])
{
    unsigned char bufx4[4 * SPX_ADDR_BYTES];
    /* Since SPX_N may be smaller than 32, we need a temporary buffer. */
    unsigned char outbuf[4 * 32];
    unsigned int i;

    (void)key; /* Suppress an 'unused parameter' warning. */

    for (i = 0; i < 4; i++) {
        addr_to_bytes(bufx4 + i*SPX_ADDR_BYTES, addrx4 + i*8);
    }

    haraka256_skx4(outbuf, bufx4);

    memcpy(out0, outbuf, SPX_N);
    memcpy(out1, outbuf + 32, SPX_N);
    memcpy(out2, outbuf + 64, SPX_N);
    memcpy(out3, outbuf + 96, SPX_N);
}

/**
 * 4-way parallel version of thash; takes 4x as much input and output
 */
void thashx4(unsigned char *out0,
             unsigned char *out1,
             unsigned char *out2,
             unsigned char *out3,
             const unsigned char *in0,
             const unsigned char *in1,
             const unsigned char *in2,
             const unsigned char *in3, unsigned int inblocks,
             const unsigned char *pub_seed, uint32_t addrx4[4*8])
{
    unsigned char buf0[SPX_ADDR_BYTES + inblocks*SPX_N];
    unsigned char buf1[SPX_ADDR_BYTES + inblocks*SPX_N];
    unsigned char buf2[SPX_ADDR_BYTES + inblocks*SPX_N];
    unsigned char buf3[SPX_ADDR_BYTES + inblocks*SPX_N];
    unsigned char bitmask0[inblocks * SPX_N];
    unsigned char bitmask1[inblocks * SPX_N];
    unsigned char bitmask2[inblocks * SPX_N];
    unsigned char bitmask3[inblocks * SPX_N];
    unsigned int i;

    (void)pub_seed; /* Suppress an 'unused parameter' warning. */

    addr_to_bytes(buf0, addrx4 + 0*8);
    addr_to_bytes(buf1, addrx4 + 1*8);
    addr_to_bytes(buf2, addrx4 + 2*8);
    addr_to_bytes(buf3, addrx4 + 3*8);

    if (inblocks == 1) {
        unsigned char outbuf[32 * 4];
        unsigned char buf_tmp[64 * 4];
        memset(buf_tmp, 0, 64 * 4);

        // Generate masks first in buffer

        memcpy(buf_tmp,      buf0, SPX_ADDR_BYTES + SPX_N);
        memcpy(buf_tmp + 32, buf1, SPX_ADDR_BYTES + SPX_N);
        memcpy(buf_tmp + 64, buf2, SPX_ADDR_BYTES + SPX_N);
        memcpy(buf_tmp + 96, buf3, SPX_ADDR_BYTES + SPX_N);

        haraka256x4(outbuf, buf_tmp);

        memcpy(buf_tmp,       buf0, SPX_ADDR_BYTES + SPX_N);
        memcpy(buf_tmp + 64,  buf1, SPX_ADDR_BYTES + SPX_N);
        memcpy(buf_tmp + 128, buf2, SPX_ADDR_BYTES + SPX_N);
        memcpy(buf_tmp + 192, buf3, SPX_ADDR_BYTES + SPX_N);        
        
        for (i = 0; i < SPX_N; i++) {
            buf_tmp[SPX_ADDR_BYTES + i]       = in0[i] ^ outbuf[i];
            buf_tmp[SPX_ADDR_BYTES + i + 64]  = in1[i] ^ outbuf[i + 32];
            buf_tmp[SPX_ADDR_BYTES + i + 128] = in2[i] ^ outbuf[i + 64];
            buf_tmp[SPX_ADDR_BYTES + i + 192] = in3[i] ^ outbuf[i + 96];
        }
        
        haraka512x4(outbuf, buf_tmp);
        
        memcpy(out0, outbuf,      SPX_N);
        memcpy(out1, outbuf + 32, SPX_N);
        memcpy(out2, outbuf + 64, SPX_N);
        memcpy(out3, outbuf + 96, SPX_N);
    } else {
        /* All other tweakable hashes*/
        haraka_Sx4(bitmask0, bitmask1, bitmask2, bitmask3, inblocks * SPX_N, 
                   buf0, buf1, buf2, buf3, SPX_ADDR_BYTES);

        for (i = 0; i < inblocks * SPX_N; i++) {
            buf0[SPX_ADDR_BYTES + i] = in0[i] ^ bitmask0[i];
            buf1[SPX_ADDR_BYTES + i] = in1[i] ^ bitmask1[i];
            buf2[SPX_ADDR_BYTES + i] = in2[i] ^ bitmask2[i];
            buf3[SPX_ADDR_BYTES + i] = in3[i] ^ bitmask3[i];
        }

        haraka_Sx4(out0, out1, out2, out3, SPX_N, 
                    buf0, buf1, buf2, buf3, SPX_ADDR_BYTES + inblocks*SPX_N);
    }
}
