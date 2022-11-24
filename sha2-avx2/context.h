#ifndef SPX_CONTEXT_H
#define SPX_CONTEXT_H

#include <stdint.h>

#include "params.h"
#include "sha2.h"
#include "sha256avx.h"
#include "sha512x4.h"

typedef struct {
    uint8_t pub_seed[SPX_N];
    uint8_t sk_seed[SPX_N];

    sha256ctx state_seeded;
    sha256x8ctx statex8_seeded;
#if SPX_SHA512
    sha512ctx state_seeded_512;
    sha512x4ctx statex4_seeded_512;
#endif
} spx_ctx;


#define initialize_hash_function SPX_NAMESPACE(initialize_hash_function)
void initialize_hash_function(spx_ctx *ctx);

#define free_hash_function SPX_NAMESPACE(free_hash_function)
void free_hash_function(spx_ctx *ctx);

#endif
