#include <stdint.h>
#include <string.h>

#include "thash.h"
#include "address.h"
#include "params.h"
#include "sha256.h"

/**
 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
 */
void thash(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const unsigned char *pub_seed, uint32_t addr[8])
{
    unsigned char buf[SPX_SHA256_BLOCK_BYTES + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N];
    unsigned char outbuf[SPX_SHA256_OUTPUT_BYTES];

    memcpy(buf, pub_seed, SPX_N);
    /* Pad to a full input block, to allow precomputation */
    memset(buf + SPX_N, 0, SPX_SHA256_BLOCK_BYTES - SPX_N);
    compress_address(buf + SPX_SHA256_BLOCK_BYTES, addr);
    memcpy(buf + SPX_SHA256_BLOCK_BYTES + SPX_SHA256_ADDR_BYTES, in, inblocks * SPX_N);

    sha256(outbuf, buf, SPX_SHA256_BLOCK_BYTES + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N);
    memcpy(out, outbuf, SPX_N);
}
