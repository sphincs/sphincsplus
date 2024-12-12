/* SPDX-License-Identifier: (LicenseRef-SPHINCS-PLUS-Public-Domain OR CC0-1.0 OR 0BSD OR MIT-0) AND MIT
 * Copyright: TBD
 * */

#ifndef SPX_THASHX2_H
#define SPX_THASHX2_H

#include <stdint.h>
#include "context.h"
#include "params.h"

#define thashx2 SPX_NAMESPACE(thashx2)
void thashx2(unsigned char *out0,
             unsigned char *out1,
             const unsigned char *in0,
             const unsigned char *in1,
             unsigned int inblocks,
             const spx_ctx *ctx, uint32_t addrx2[2*8]);

#endif
