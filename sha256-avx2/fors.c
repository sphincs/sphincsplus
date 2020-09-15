#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "fors.h"
#include "utils.h"
#include "utilsx8.h"
#include "hash.h"
#include "hashx8.h"
#include "thash.h"
#include "thashx8.h"
#include "address.h"

static void fors_gen_sk(unsigned char *sk, const unsigned char *sk_seed,
                        uint32_t fors_leaf_addr[8])
{
    prf_addr(sk, sk_seed, fors_leaf_addr);
}

static void fors_gen_skx8(unsigned char *sk0,
                          unsigned char *sk1,
                          unsigned char *sk2,
                          unsigned char *sk3,
                          unsigned char *sk4,
                          unsigned char *sk5,
                          unsigned char *sk6,
                          unsigned char *sk7, const unsigned char *sk_seed,
                          uint32_t fors_leaf_addrx8[8*8])
{
    prf_addrx8(sk0, sk1, sk2, sk3, sk4, sk5, sk6, sk7,
               sk_seed, fors_leaf_addrx8);
}

static void fors_sk_to_leaf(unsigned char *leaf, const unsigned char *sk,
                            const unsigned char *pub_seed,
                            uint32_t fors_leaf_addr[8])
{
    thash(leaf, sk, 1, pub_seed, fors_leaf_addr);
}

static void fors_sk_to_leafx8(unsigned char *leaf0,
                              unsigned char *leaf1,
                              unsigned char *leaf2,
                              unsigned char *leaf3,
                              unsigned char *leaf4,
                              unsigned char *leaf5,
                              unsigned char *leaf6,
                              unsigned char *leaf7,
                              const unsigned char *sk0,
                              const unsigned char *sk1,
                              const unsigned char *sk2,
                              const unsigned char *sk3,
                              const unsigned char *sk4,
                              const unsigned char *sk5,
                              const unsigned char *sk6,
                              const unsigned char *sk7,
                              const unsigned char *pub_seed,
                              uint32_t fors_leaf_addrx8[8*8])
{
    thashx8(leaf0, leaf1, leaf2, leaf3, leaf4, leaf5, leaf6, leaf7,
            sk0, sk1, sk2, sk3, sk4, sk5, sk6, sk7,
            1, pub_seed, fors_leaf_addrx8);
}

struct fors_gen_leaf_info {
    uint32_t leaf_addrx[8*8];
};

static void fors_gen_leafx8(unsigned char *leaf,
                            const unsigned char *sk_seed,
                            const unsigned char *pub_seed,
                            uint32_t addr_idx, void *info)
{
    struct fors_gen_leaf_info *fors_info = info;
    uint32_t *fors_leaf_addrx8 = fors_info->leaf_addrx;
    unsigned int j;

    /* Only set the parts that the caller doesn't set */
    for (j = 0; j < 8; j++) {
        set_tree_index(fors_leaf_addrx8 + j*8, addr_idx + j);
    }

    fors_gen_skx8(leaf + 0*SPX_N,
                  leaf + 1*SPX_N,
                  leaf + 2*SPX_N,
                  leaf + 3*SPX_N,
                  leaf + 4*SPX_N,
                  leaf + 5*SPX_N,
                  leaf + 6*SPX_N,
                  leaf + 7*SPX_N,
                  sk_seed, fors_leaf_addrx8);
    fors_sk_to_leafx8(leaf + 0*SPX_N,
                  leaf + 1*SPX_N,
                  leaf + 2*SPX_N,
                  leaf + 3*SPX_N,
                  leaf + 4*SPX_N,
                  leaf + 5*SPX_N,
                  leaf + 6*SPX_N,
                  leaf + 7*SPX_N,
                  leaf + 0*SPX_N,
                  leaf + 1*SPX_N,
                  leaf + 2*SPX_N,
                  leaf + 3*SPX_N,
                  leaf + 4*SPX_N,
                  leaf + 5*SPX_N,
                  leaf + 6*SPX_N,
                  leaf + 7*SPX_N,
                  pub_seed, fors_leaf_addrx8);
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
    uint32_t indices[SPX_FORS_TREES];
    unsigned char roots[SPX_FORS_TREES * SPX_N];
    uint32_t fors_tree_addr[8*8] = {0};
    struct fors_gen_leaf_info fors_info = {0};
    uint32_t *fors_leaf_addr = fors_info.leaf_addrx;
    uint32_t fors_pk_addr[8] = {0};
    uint32_t idx_offset;
    unsigned int i;

    for (i=0; i<8; i++) {
        copy_keypair_addr(fors_tree_addr + 8*i, fors_addr);
        set_type(fors_tree_addr + 8*i, SPX_ADDR_TYPE_FORSTREE);
        copy_keypair_addr(fors_leaf_addr + 8*i, fors_addr);
        set_type(fors_leaf_addr + 8*i, SPX_ADDR_TYPE_FORSTREE);
    }
    copy_keypair_addr(fors_pk_addr, fors_addr);
    set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices(indices, m);

    for (i = 0; i < SPX_FORS_TREES; i++) {
        idx_offset = i * (1 << SPX_FORS_HEIGHT);

        set_tree_height(fors_tree_addr, 0);
        set_tree_index(fors_tree_addr, indices[i] + idx_offset);

        /* Include the secret key part that produces the selected leaf node. */
        fors_gen_sk(sig, sk_seed, fors_tree_addr);
        sig += SPX_N;

        /* Compute the authentication path for this leaf node. */
        treehashx8(roots + i*SPX_N, sig, sk_seed, pub_seed,
                 indices[i], idx_offset, SPX_FORS_HEIGHT, fors_gen_leafx8,
                 fors_tree_addr, &fors_info);

        sig += SPX_N * SPX_FORS_HEIGHT;
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
