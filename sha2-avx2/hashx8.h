/* SPDX-License-Identifier: (LicenseRef-SPHINCS-PLUS-Public-Domain OR CC0-1.0 OR 0BSD OR MIT-0) AND MIT
 * Copyright: TBD
 * */

#ifndef SPX_HASHX8_H
#define SPX_HASHX8_H

#include <stdint.h>
#include "params.h"

#define prf_addrx8 SPX_NAMESPACE(prf_addrx8)
void prf_addrx8(unsigned char *out0,
                unsigned char *out1,
                unsigned char *out2,
                unsigned char *out3,
                unsigned char *out4,
                unsigned char *out5,
                unsigned char *out6,
                unsigned char *out7,
                const spx_ctx *ctx,
                const uint32_t addrx8[8*8]);

#endif
