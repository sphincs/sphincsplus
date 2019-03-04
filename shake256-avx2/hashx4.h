#ifndef SPX_HASHX4_H
#define SPX_HASHX4_H

#include <stdint.h>

void prf_addrx4(unsigned char *out0,
                unsigned char *out1,
                unsigned char *out2,
                unsigned char *out3,
                const unsigned char *key,
                const uint32_t addrx4[4*8]);

#endif
