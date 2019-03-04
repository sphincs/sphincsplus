#include <stdint.h>
#include <string.h>

#include "address.h"
#include "params.h"
#include "harakax4.h"
#include "hashx4.h"

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
