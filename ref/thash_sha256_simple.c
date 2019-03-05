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
    unsigned char buf[SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N];
    unsigned char outbuf[SPX_SHA256_OUTPUT_BYTES];

    memcpy(buf, pub_seed, SPX_N);
    addr_to_bytes(buf + SPX_N, addr);
    memcpy(buf + SPX_N + SPX_ADDR_BYTES, in, inblocks * SPX_N);

    SHA256(buf, SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N, outbuf);
    memcpy(out, outbuf, SPX_N);
}
