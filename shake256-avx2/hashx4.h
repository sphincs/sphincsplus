#ifndef SPX_HASHX4_H
#define SPX_HASHX4_H

#include <stdint.h>
#include "params.h"

void prf_addrx4(unsigned char *out0,
                unsigned char *out1,
                unsigned char *out2,
                unsigned char *out3,
                const unsigned char *key,
                const uint32_t addrx4[4*8]);

void thashx4(unsigned char *out0,
             unsigned char *out1,
             unsigned char *out2,
             unsigned char *out3,
             const unsigned char *in0,
             const unsigned char *in1,
             const unsigned char *in2,
             const unsigned char *in3, unsigned int inblocks,
             const unsigned char *pub_seed, uint32_t addrx4[4*8]);

#endif
