#ifndef SPX_CONTEXT_H
#define SPX_CONTEXT_H

#include <stdint.h>

#include "params.h"
#include "immintrin.h"

typedef struct {
    uint8_t pub_seed[SPX_N];
    uint8_t sk_seed[SPX_N];

    __m128i rc[40];
} spx_ctx;

#endif
