#include <stdint.h>
#include <string.h>

#include "thash.h"
#include "address.h"
#include "params.h"

#include "haraka.h"

/**
 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
 */
void thash(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const unsigned char *pub_seed, uint32_t addr[8])
{
    unsigned char buf[SPX_ADDR_BYTES + inblocks*SPX_N];
    unsigned char outbuf[32];
    unsigned char buf_tmp[64];

    (void)pub_seed; /* Suppress an 'unused parameter' warning. */

    if (inblocks == 1) {
        /* F function */
        /* Since SPX_N may be smaller than 32, we need a temporary buffer. */
        memset(buf_tmp, 0, 64);
        addr_to_bytes(buf_tmp, addr);
        memcpy(buf_tmp + SPX_ADDR_BYTES, in, SPX_N);

        haraka512(outbuf, buf_tmp);
        memcpy(out, outbuf, SPX_N);
    } else {
        /* All other tweakable hashes*/
        addr_to_bytes(buf, addr);
        memcpy(buf + SPX_ADDR_BYTES, in, inblocks * SPX_N);

        haraka_S(out, SPX_N, buf, SPX_ADDR_BYTES + inblocks*SPX_N);
    }
}
