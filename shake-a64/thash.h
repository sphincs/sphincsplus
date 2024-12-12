/* SPDX-License-Identifier: (LicenseRef-SPHINCS-PLUS-Public-Domain OR CC0-1.0 OR 0BSD OR MIT-0) AND MIT
 * Copyright: TBD
 * */

#ifndef SPX_THASHX2_AS_ONE
#define SPX_THASHX2_AS_ONE

#include <stdint.h>
#include "context.h"

void thash(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8]);


#endif

