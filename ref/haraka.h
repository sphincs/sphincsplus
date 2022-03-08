#ifndef SPX_HARAKA_H
#define SPX_HARAKA_H

#include "context.h"

/* Tweak constants with seed */
void tweak_constants(spx_ctx *ctx);

/* Haraka Sponge */
void haraka_S_inc_init(uint8_t *s_inc);
void haraka_S_inc_absorb(uint8_t *s_inc, const uint8_t *m, size_t mlen,
        const spx_ctx *ctx);
void haraka_S_inc_finalize(uint8_t *s_inc);
void haraka_S_inc_squeeze(uint8_t *out, size_t outlen, uint8_t *s_inc,
        const spx_ctx *ctx);
void haraka_S(unsigned char *out, unsigned long long outlen,
              const unsigned char *in, unsigned long long inlen,
              const spx_ctx *ctx);

/* Applies the 512-bit Haraka permutation to in. */
void haraka512_perm(unsigned char *out, const unsigned char *in,
        const spx_ctx *ctx);

/* Implementation of Haraka-512 */
void haraka512(unsigned char *out, const unsigned char *in,
        const spx_ctx *ctx);

/* Implementation of Haraka-256 */
void haraka256(unsigned char *out, const unsigned char *in,
        const spx_ctx *ctx);

#endif
