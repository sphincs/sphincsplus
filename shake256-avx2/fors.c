#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "fors.h"
#include "utils.h"
#include "utilsx4.h"
#include "hash.h"
#include "hashx4.h"
#include "thash.h"
#include "thashx4.h"
#include "address.h"

static void fors_gen_skx4(unsigned char *sk0,
                          unsigned char *sk1,
                          unsigned char *sk2,
                          unsigned char *sk3, const unsigned char *sk_seed,
                          uint32_t fors_leaf_addrx4[4*8])
{
    prf_addrx4(sk0, sk1, sk2, sk3, sk_seed, fors_leaf_addrx4);
}

static void fors_sk_to_leaf(unsigned char *leaf, const unsigned char *sk,
                            const unsigned char *pub_seed,
                            uint32_t fors_leaf_addr[8])
{
    thash(leaf, sk, 1, pub_seed, fors_leaf_addr);
}

static void fors_sk_to_leafx4(unsigned char *leaf0,
                              unsigned char *leaf1,
                              unsigned char *leaf2,
                              unsigned char *leaf3,
                              const unsigned char *sk0,
                              const unsigned char *sk1,
                              const unsigned char *sk2,
                              const unsigned char *sk3,
                              const unsigned char *pub_seed,
                              uint32_t fors_leaf_addrx4[4*8])
{
    thashx4(leaf0, leaf1, leaf2, leaf3,
            sk0, sk1, sk2, sk3, 1, pub_seed, fors_leaf_addrx4);
}

static void fors_gen_leafx4(unsigned char *leaf0,
                            unsigned char *leaf1,
                            unsigned char *leaf2,
                            unsigned char *leaf3,
                            const unsigned char *sk_seed,
                            const unsigned char *pub_seed,
                            uint32_t addr_idx0,
                            uint32_t addr_idx1,
                            uint32_t addr_idx2,
                            uint32_t addr_idx3,
                            const uint32_t fors_tree_addr[8])
{
    uint32_t fors_leaf_addrx4[4*8] = {0};
    unsigned int j;

    /* Only copy the parts that must be kept in fors_leaf_addrx4. */
    for (j = 0; j < 4; j++) {
        copy_keypair_addr(fors_leaf_addrx4 + j*8, fors_tree_addr);
        set_type(fors_leaf_addrx4 + j*8, SPX_ADDR_TYPE_FORSTREE);
    }

    set_tree_index(fors_leaf_addrx4 + 0*8, addr_idx0);
    set_tree_index(fors_leaf_addrx4 + 1*8, addr_idx1);
    set_tree_index(fors_leaf_addrx4 + 2*8, addr_idx2);
    set_tree_index(fors_leaf_addrx4 + 3*8, addr_idx3);

    fors_gen_skx4(leaf0, leaf1, leaf2, leaf3, sk_seed, fors_leaf_addrx4);
    fors_sk_to_leafx4(leaf0, leaf1, leaf2, leaf3,
                      leaf0, leaf1, leaf2, leaf3, pub_seed, fors_leaf_addrx4);
}

/**
 * Interprets m as SPX_FORS_HEIGHT-bit unsigned integers.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
 * Assumes indices has space for SPX_FORS_TREES integers.
 */
static void message_to_indices(uint32_t *indices, const unsigned char *m)
{
    unsigned int i, j;
    unsigned int offset = 0;

    for (i = 0; i < SPX_FORS_TREES; i++) {
        indices[i] = 0;
        for (j = 0; j < SPX_FORS_HEIGHT; j++) {
            indices[i] ^= ((m[offset >> 3] >> (offset & 0x7)) & 0x1) << j;
            offset++;
        }
    }
}

/**
 * Signs a message m, deriving the secret key from sk_seed and the FTS address.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
 */
void fors_sign(unsigned char *sig, unsigned char *pk,
               const unsigned char *m,
               const unsigned char *sk_seed, const unsigned char *pub_seed,
               const uint32_t fors_addr[8])
{
    /* Round up to multiple of 4 to prevent out-of-bounds for x4 parallelism */
    uint32_t indices[(SPX_FORS_TREES + 3) & ~3] = {0};
    unsigned char roots[((SPX_FORS_TREES + 3) & ~3) * SPX_N];
    /* Sign to a buffer, since we may not have a nice multiple of 4 and would
       otherwise overrun the signature. */
    unsigned char sigbufx4[4 * SPX_N * (1 + SPX_FORS_HEIGHT)];
    uint32_t fors_tree_addrx4[4*8] = {0};
    uint32_t fors_pk_addr[8] = {0};
    uint32_t idx_offset[4] = {0};
    unsigned int i, j;

    for (j = 0; j < 4; j++) {
        copy_keypair_addr(fors_tree_addrx4 + j*8, fors_addr);
        set_type(fors_tree_addrx4 + j*8, SPX_ADDR_TYPE_FORSTREE);
    }

    copy_keypair_addr(fors_pk_addr, fors_addr);
    set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices(indices, m);

    for (i = 0; i < ((SPX_FORS_TREES + 3) & ~0x3); i += 4) {
        for (j = 0; j < 4; j++) {
            if (i + j < SPX_FORS_TREES) {
                idx_offset[j] = (i + j) * (1 << SPX_FORS_HEIGHT);

                set_tree_height(fors_tree_addrx4 + j*8, 0);
                set_tree_index(fors_tree_addrx4 + j*8,
                               indices[i + j] + idx_offset[j]);
            }
        }

        /* Include the secret key part that produces the selected leaf nodes. */
        fors_gen_skx4(sigbufx4 + 0*SPX_N,
                      sigbufx4 + 1*SPX_N,
                      sigbufx4 + 2*SPX_N,
                      sigbufx4 + 3*SPX_N,
                      sk_seed, fors_tree_addrx4);

        treehashx4(roots + i*SPX_N, sigbufx4 + 4*SPX_N, sk_seed, pub_seed,
                   &indices[i], idx_offset, SPX_FORS_HEIGHT, fors_gen_leafx4,
                   fors_tree_addrx4);

        for (j = 0; j < 4; j++) {
            if (i + j < SPX_FORS_TREES) {
                memcpy(sig, sigbufx4 + j*SPX_N, SPX_N);
                memcpy(sig + SPX_N,
                       sigbufx4 + 4*SPX_N + j*SPX_N*SPX_FORS_HEIGHT,
                       SPX_N*SPX_FORS_HEIGHT);
                sig += SPX_N * (1 + SPX_FORS_HEIGHT);
            }
        }
    }

    /* Hash horizontally across all tree roots to derive the public key. */
    thash(pk, roots, SPX_FORS_TREES, pub_seed, fors_pk_addr);
}

/**
 * Derives the FORS public key from a signature.
 * This can be used for verification by comparing to a known public key, or to
 * subsequently verify a signature on the derived public key. The latter is the
 * typical use-case when used as an FTS below an OTS in a hypertree.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
 */
void fors_pk_from_sig(unsigned char *pk,
                      const unsigned char *sig, const unsigned char *m,
                      const unsigned char *pub_seed,
                      const uint32_t fors_addr[8])
{
    uint32_t indices[SPX_FORS_TREES];
    unsigned char roots[SPX_FORS_TREES * SPX_N];
    unsigned char leaf[SPX_N];
    uint32_t fors_tree_addr[8] = {0};
    uint32_t fors_pk_addr[8] = {0};
    uint32_t idx_offset;
    unsigned int i;

    copy_keypair_addr(fors_tree_addr, fors_addr);
    copy_keypair_addr(fors_pk_addr, fors_addr);

    set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
    set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices(indices, m);

    for (i = 0; i < SPX_FORS_TREES; i++) {
        idx_offset = i * (1 << SPX_FORS_HEIGHT);

        set_tree_height(fors_tree_addr, 0);
        set_tree_index(fors_tree_addr, indices[i] + idx_offset);

        /* Derive the leaf from the included secret key part. */
        fors_sk_to_leaf(leaf, sig, pub_seed, fors_tree_addr);
        sig += SPX_N;

        /* Derive the corresponding root node of this tree. */
        compute_root(roots + i*SPX_N, leaf, indices[i], idx_offset,
                     sig, SPX_FORS_HEIGHT, pub_seed, fors_tree_addr);
        sig += SPX_N * SPX_FORS_HEIGHT;
    }

    /* Hash horizontally across all tree roots to derive the public key. */
    thash(pk, roots, SPX_FORS_TREES, pub_seed, fors_pk_addr);
}
