#include <stdint.h>
#include <string.h>

#include "address.h"
#include "haraka.h"
#include "hash.h"
#include "params.h"
#include "utils.h"

void SPX_initialize_hash_function(
    hash_state *hash_state_seeded,
    const unsigned char *pub_seed, const unsigned char *sk_seed) {
    SPX_tweak_constants(hash_state_seeded, pub_seed, sk_seed, SPX_N);
}

/*
 * Computes PRF(key, addr), given a secret key of SPX_N bytes and an address
 */
void SPX_prf_addr(
    unsigned char *out, const unsigned char *key, const uint32_t addr[8],
    const hash_state *hash_state_seeded) {
    unsigned char buf[SPX_ADDR_BYTES];
    /* Since SPX_N may be smaller than 32, we need a temporary buffer. */
    unsigned char outbuf[32];

    (void)key; /* Suppress an 'unused parameter' warning. */

    SPX_addr_to_bytes(buf, addr);
    SPX_haraka256_sk(outbuf, buf, hash_state_seeded);
    memcpy(out, outbuf, SPX_N);
}

/**
 * Computes the message-dependent randomness R, using a secret seed and an
 * optional randomization value as well as the message.
 */
void SPX_gen_message_random(
    unsigned char *R,
    const unsigned char *sk_prf, const unsigned char *optrand,
    const unsigned char *m, size_t mlen,
    const hash_state *hash_state_seeded) {
    uint8_t s_inc[65];

    SPX_haraka_S_inc_init(s_inc);
    SPX_haraka_S_inc_absorb(s_inc, sk_prf, SPX_N, hash_state_seeded);
    SPX_haraka_S_inc_absorb(s_inc, optrand, SPX_N, hash_state_seeded);
    SPX_haraka_S_inc_absorb(s_inc, m, mlen, hash_state_seeded);
    SPX_haraka_S_inc_finalize(s_inc);
    SPX_haraka_S_inc_squeeze(R, SPX_N, s_inc, hash_state_seeded);
}

/**
 * Computes the message hash using R, the public key, and the message.
 * Outputs the message digest and the index of the leaf. The index is split in
 * the tree index and the leaf index, for convenient copying to an address.
 */
void SPX_hash_message(
    unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
    const unsigned char *R, const unsigned char *pk,
    const unsigned char *m, size_t mlen,
    const hash_state *hash_state_seeded) {
#define SPX_TREE_BITS (SPX_TREE_HEIGHT * (SPX_D - 1))
#define SPX_TREE_BYTES ((SPX_TREE_BITS + 7) / 8)
#define SPX_LEAF_BITS SPX_TREE_HEIGHT
#define SPX_LEAF_BYTES ((SPX_LEAF_BITS + 7) / 8)
#define SPX_DGST_BYTES (SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES)

    unsigned char buf[SPX_DGST_BYTES];
    unsigned char *bufp = buf;
    uint8_t s_inc[65];

    SPX_haraka_S_inc_init(s_inc);
    SPX_haraka_S_inc_absorb(s_inc, R, SPX_N, hash_state_seeded);
    SPX_haraka_S_inc_absorb(s_inc, pk + SPX_N, SPX_N, hash_state_seeded);
    SPX_haraka_S_inc_absorb(s_inc, m, mlen, hash_state_seeded);
    SPX_haraka_S_inc_finalize(s_inc);
    SPX_haraka_S_inc_squeeze(buf, SPX_DGST_BYTES, s_inc, hash_state_seeded);

    memcpy(digest, bufp, SPX_FORS_MSG_BYTES);
    bufp += SPX_FORS_MSG_BYTES;

    *tree = SPX_bytes_to_ull(bufp, SPX_TREE_BYTES);
    *tree &= (~(uint64_t)0) >> (64 - SPX_TREE_BITS);
    bufp += SPX_TREE_BYTES;

    *leaf_idx = (uint32_t)SPX_bytes_to_ull(
                    bufp, SPX_LEAF_BYTES);
    *leaf_idx &= (~(uint32_t)0) >> (32 - SPX_LEAF_BITS);
}
