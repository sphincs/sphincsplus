#ifndef SPX_CONTEXT_H
#define SPX_CONTEXT_H

#include <stdint.h>

#include "params.h"

typedef struct {
    uint8_t pub_seed[SPX_N];
    uint8_t sk_seed[SPX_N];

    uint8_t state_seeded[40];
#if SPX_SHA512
    uint8_t state_seeded_512[72];
#endif
} spx_ctx;

#endif
