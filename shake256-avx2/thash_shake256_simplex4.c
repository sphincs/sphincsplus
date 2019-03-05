#include <stdint.h>
#include <string.h>

#include "thashx4.h"
#include "address.h"
#include "params.h"

#include "fips202x4.h"

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
    unsigned char buf0[SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N];
    unsigned char buf1[SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N];
    unsigned char buf2[SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N];
    unsigned char buf3[SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N];

    memcpy(buf0, pub_seed, SPX_N);
    memcpy(buf1, pub_seed, SPX_N);
    memcpy(buf2, pub_seed, SPX_N);
    memcpy(buf3, pub_seed, SPX_N);
    addr_to_bytes(buf0 + SPX_N, addrx4 + 0*8);
    addr_to_bytes(buf1 + SPX_N, addrx4 + 1*8);
    addr_to_bytes(buf2 + SPX_N, addrx4 + 2*8);
    addr_to_bytes(buf3 + SPX_N, addrx4 + 3*8);
    memcpy(buf0 + SPX_N + SPX_ADDR_BYTES, in0, inblocks * SPX_N);
    memcpy(buf1 + SPX_N + SPX_ADDR_BYTES, in1, inblocks * SPX_N);
    memcpy(buf2 + SPX_N + SPX_ADDR_BYTES, in2, inblocks * SPX_N);
    memcpy(buf3 + SPX_N + SPX_ADDR_BYTES, in3, inblocks * SPX_N);

    shake256x4(out0, out1, out2, out3, SPX_N,
               buf0, buf1, buf2, buf3, SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N);
}