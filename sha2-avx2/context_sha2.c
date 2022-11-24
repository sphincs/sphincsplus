#include <immintrin.h>

#include "context.h"

static uint32_t load_bigendian_32(const uint8_t *x) {
    return (uint32_t)(x[3]) | (((uint32_t)(x[2])) << 8) |
           (((uint32_t)(x[1])) << 16) | (((uint32_t)(x[0])) << 24);
}

/**
 * Absorb the constant pub_seed using one round of the compression function
 * This initializes state_seeded and state_seeded_512, which can then be
 * reused in thash
 **/
static void seed_state(spx_ctx *ctx) {
    uint8_t block[SPX_SHA512_BLOCK_BYTES];
    size_t i;

    for (i = 0; i < SPX_N; ++i) {
        block[i] = ctx->pub_seed[i];
    }
    for (i = SPX_N; i < SPX_SHA512_BLOCK_BYTES; ++i) {
        block[i] = 0;
    }
    /* block has been properly initialized for both SHA-256 and SHA-512 */

    sha256_inc_init(&ctx->state_seeded);
    sha256_inc_blocks(&ctx->state_seeded, block, 1);

    // this still assumes internal representation of the SHA256x1 API.
    // should be replaced by proper initialization.
    for (size_t i = 0; i < 8; i++) {
        uint32_t t = load_bigendian_32(((uint8_t*)&ctx->state_seeded.ctx) + 4*i);
        ctx->statex8_seeded.s[i] = _mm256_set_epi32(t, t, t, t, t, t, t, t);
    }

    ctx->statex8_seeded.datalen = 0;
    ctx->statex8_seeded.msglen = 512;

#if SPX_SHA512
    sha512_inc_init(&ctx->state_seeded_512);
    sha512_inc_blocks(&ctx->state_seeded_512, block, 1);

    // this still assumes internal representation of the SHA512x1 API.
    // should be replaced by proper initialization.
    uint8_t *seed = (uint8_t*)&ctx->state_seeded_512.ctx;
    for (i = 0; i < 8; i++) {
        uint64_t t = (uint64_t)(seed[7]) | (((uint64_t)(seed[6])) << 8) |
           (((uint64_t)(seed[5])) << 16) | (((uint64_t)(seed[4])) << 24) |
           (((uint64_t)(seed[3])) << 32) | (((uint64_t)(seed[2])) << 40) |
           (((uint64_t)(seed[1])) << 48) | (((uint64_t)(seed[0])) << 56);
        ctx->statex4_seeded_512.s[i] = _mm256_set_epi64x(t, t, t, t);
        seed += 8;
    }

    ctx->statex4_seeded_512.datalen = 0;
    ctx->statex4_seeded_512.msglen = 1024;


#endif
}


/* For SHA, we initialize the hash function at the start */
void initialize_hash_function(spx_ctx *ctx)
{
    seed_state(ctx);
}

/* Free the incremental hashing context for heap-based SHA2 APIs */
void free_hash_function(spx_ctx *ctx)
{
    sha256_inc_ctx_release(&ctx->state_seeded);
#if SPX_SHA512
    sha512_inc_ctx_release(&ctx->state_seeded_512);
#endif
}
