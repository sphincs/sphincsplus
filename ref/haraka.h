#ifndef SPX_HARAKA_H
#define SPX_HARAKA_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint64_t tweaked512_rc64[10][8];
    uint32_t tweaked256_rc32[10][8];
    uint32_t tweaked256_rc32_sseed[10][8];
} harakactx;

/* Tweak constants with seed */
void SPX_tweak_constants(
    harakactx *state,
    const unsigned char *pk_seed, const unsigned char *sk_seed,
    unsigned long long seed_length);

/* Haraka Sponge */
void SPX_haraka_S_inc_init(uint8_t *s_inc);
void SPX_haraka_S_inc_absorb(uint8_t *s_inc, const uint8_t *m, size_t mlen, const harakactx *state);
void SPX_haraka_S_inc_finalize(uint8_t *s_inc);
void SPX_haraka_S_inc_squeeze(uint8_t *out, size_t outlen, uint8_t *s_inc, const harakactx *state);
void SPX_haraka_S(
    unsigned char *out, unsigned long long outlen,
    const unsigned char *in, unsigned long long inlen, const harakactx *state);

/* Applies the 512-bit Haraka permutation to in. */
void SPX_haraka512_perm(unsigned char *out, const unsigned char *in, const harakactx *state);

/* Implementation of Haraka-512 */
void SPX_haraka512(unsigned char *out, const unsigned char *in, const harakactx *state);

/* Implementation of Haraka-256 */
void SPX_haraka256(unsigned char *out, const unsigned char *in, const harakactx *state);

/* Implementation of Haraka-256 using sk.seed constants */
void SPX_haraka256_sk(unsigned char *out, const unsigned char *in, const harakactx *state);

#endif
