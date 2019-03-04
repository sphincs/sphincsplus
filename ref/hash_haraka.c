#include <stdint.h>
#include <string.h>

#include "address.h"
#include "utils.h"
#include "params.h"

#include "haraka.h"
#include "hash.h"

void initialize_hash_function(const unsigned char *pk_seed,
                              const unsigned char *sk_seed)
{
    tweak_constants(pk_seed, sk_seed, SPX_N);
}

/*
 * Computes PRF(key, addr), given a secret key of SPX_N bytes and an address
 */
void prf_addr(unsigned char *out, const unsigned char *key,
              const uint32_t addr[8])
{
    unsigned char buf[SPX_ADDR_BYTES];
    /* Since SPX_N may be smaller than 32, we need a temporary buffer. */
    unsigned char outbuf[32];

    (void)key; /* Suppress an 'unused parameter' warning. */

    addr_to_bytes(buf, addr);
    haraka256_sk(outbuf, buf);
    memcpy(out, outbuf, SPX_N);
}

/**
 * Computes the message-dependent randomness R, using a secret seed and an
 * optional randomization value prefixed to the message.
 * This requires m to have at least 2*SPX_N bytes * bytes of space available in
 * front of the pointer, i.e. before the message to use for the prefix. This is
 * necessary to prevent having to move the message around (and allocate memory
 * for it).
 */
void gen_message_random(unsigned char *R, const unsigned char *sk_prf,
                        const unsigned char *optrand,
                        unsigned char *m, unsigned long long mlen)
{
    memcpy(m - 2*SPX_N, sk_prf, SPX_N);
    memcpy(m - SPX_N, optrand, SPX_N);
    haraka_S(R, SPX_N, m - 2*SPX_N, mlen + 2*SPX_N);
}

/**
 * Computes the message hash using R, the public key, and the message.
 * Notably, it requires m to have SPX_N + SPX_PK_BYTES bytes of space available
 * in front of the pointer, i.e. before the message, to use for the prefix.
 * This is necessary to prevent having to move the * message around (and
 * allocate memory for it).
 * Outputs the message digest and the index of the leaf. The index is split in
 * the tree index and the leaf index, for convenient copying to an address.
 */
void hash_message(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  unsigned char *m, unsigned long long mlen)
{
#define SPX_TREE_BITS (SPX_TREE_HEIGHT * (SPX_D - 1))
#define SPX_TREE_BYTES ((SPX_TREE_BITS + 7) / 8)
#define SPX_LEAF_BITS SPX_TREE_HEIGHT
#define SPX_LEAF_BYTES ((SPX_LEAF_BITS + 7) / 8)
#define SPX_DGST_BYTES (SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES)

    unsigned char buf[SPX_DGST_BYTES];
    unsigned char *bufp = buf;

    memcpy(m - SPX_N - SPX_PK_BYTES, R, SPX_N);
    memcpy(m - SPX_PK_BYTES, pk, SPX_PK_BYTES);

    haraka_S(buf, SPX_DGST_BYTES,
             m - SPX_N - SPX_PK_BYTES, mlen + SPX_N + SPX_PK_BYTES);

    memcpy(digest, bufp, SPX_FORS_MSG_BYTES);
    bufp += SPX_FORS_MSG_BYTES;

#if SPX_TREE_BITS > 64
    #error For given height and depth, 64 bits cannot represent all subtrees
#endif

    *tree = bytes_to_ull(bufp, SPX_TREE_BYTES);
    *tree &= (~(uint64_t)0) >> (64 - SPX_TREE_BITS);
    bufp += SPX_TREE_BYTES;

    *leaf_idx = bytes_to_ull(bufp, SPX_LEAF_BYTES);
    *leaf_idx &= (~(uint32_t)0) >> (32 - SPX_LEAF_BITS);
}
