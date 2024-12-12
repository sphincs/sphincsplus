/* SPDX-License-Identifier: (LicenseRef-SPHINCS-PLUS-Public-Domain OR CC0-1.0 OR 0BSD OR MIT-0) AND MIT
 * Copyright: TBD
 * */

#ifndef SPX_HASHX2_H
#define SPX_HASHX2_H

#include <stdint.h>
#include "context.h"
#include "params.h"

#define prf_addrx2 SPX_NAMESPACE(prf_addrx2)
void prf_addrx2(unsigned char *out0,
                unsigned char *out1,
                const spx_ctx *ctx,
                const uint32_t addrx2[2*8]);

#endif
