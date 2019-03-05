#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>

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
    unsigned char bitmask[inblocks * SPX_N];
    unsigned int i;

    memcpy(buf + SPX_SHA256_BLOCK_BYTES - SPX_N, pub_seed, SPX_N);
    compress_address(buf + SPX_SHA256_BLOCK_BYTES, addr);
    mgf1(bitmask, inblocks * SPX_N, buf + SPX_SHA256_BLOCK_BYTES - SPX_N,
         SPX_N + SPX_SHA256_ADDR_BYTES);

    /* Pad to a full input block, to allow precomputation */
    memcpy(buf, pub_seed, SPX_N);
    memset(buf + SPX_N, 0, SPX_SHA256_BLOCK_BYTES - SPX_N);
    for (i = 0; i < inblocks * SPX_N; i++) {
        buf[SPX_SHA256_BLOCK_BYTES + SPX_SHA256_ADDR_BYTES + i] = in[i] ^ bitmask[i];
    }

    SHA256(buf, SPX_SHA256_BLOCK_BYTES + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N, outbuf);
    memcpy(out, outbuf, SPX_N);
}
