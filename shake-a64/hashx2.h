#ifndef SPX_HASHX2_H
#define SPX_HASHX2_H

#include <stdint.h>
#include "context.h"

void prf_addrx2(unsigned char *out0,
                unsigned char *out1,
                const spx_ctx *ctx,
                const uint32_t addrx2[2*8]);

#endif
