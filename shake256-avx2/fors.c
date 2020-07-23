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
 * Like compute_root, but compute four roots at the same time
 */
void compute_rootx4(
        unsigned char *root1,
        unsigned char *root2,
        unsigned char *root3,
        unsigned char *root4,
        const unsigned char *leaf1,
        const unsigned char *leaf2,
        const unsigned char *leaf3,
        const unsigned char *leaf4,
        uint32_t leaf_idx1,
        uint32_t leaf_idx2,
        uint32_t leaf_idx3,
        uint32_t leaf_idx4,
        uint32_t idx_offset1,
        uint32_t idx_offset2,
        uint32_t idx_offset3,
        uint32_t idx_offset4,
        const unsigned char *auth_path1,
        const unsigned char *auth_path2,
        const unsigned char *auth_path3,
        const unsigned char *auth_path4,
        uint32_t tree_height,
        const unsigned char *pub_seed, uint32_t addr[4*8])
{
    uint32_t i;
    unsigned char buffer1[2 * SPX_N];
    unsigned char buffer2[2 * SPX_N];
    unsigned char buffer3[2 * SPX_N];
    unsigned char buffer4[2 * SPX_N];
    unsigned char *out1, *out2, *out3, *out4;
    unsigned char *oth1, *oth2, *oth3, *oth4;

    /* If leaf_idx is odd (last bit = 1), current path element is a right child
       and auth_path has to go left. Otherwise it is the other way around. */
    if (leaf_idx1 & 1) {
        memcpy(buffer1 + SPX_N, leaf1, SPX_N);
        memcpy(buffer1, auth_path1, SPX_N);
    } else {
        memcpy(buffer1, leaf1, SPX_N);
        memcpy(buffer1 + SPX_N, auth_path1, SPX_N);
    }

    if (leaf_idx2 & 1) {
        memcpy(buffer2 + SPX_N, leaf2, SPX_N);
        memcpy(buffer2, auth_path2, SPX_N);
    } else {
        memcpy(buffer2, leaf2, SPX_N);
        memcpy(buffer2 + SPX_N, auth_path2, SPX_N);
    }

    if (leaf_idx3 & 1) {
        memcpy(buffer3 + SPX_N, leaf3, SPX_N);
        memcpy(buffer3, auth_path3, SPX_N);
    } else {
        memcpy(buffer3, leaf3, SPX_N);
        memcpy(buffer3 + SPX_N, auth_path3, SPX_N);
    }

    if (leaf_idx4 & 1) {
        memcpy(buffer4 + SPX_N, leaf4, SPX_N);
        memcpy(buffer4, auth_path4, SPX_N);
    } else {
        memcpy(buffer4, leaf4, SPX_N);
        memcpy(buffer4 + SPX_N, auth_path4, SPX_N);
    }

    auth_path1 += SPX_N;
    auth_path2 += SPX_N;
    auth_path3 += SPX_N;
    auth_path4 += SPX_N;

    for (i = 0; i < tree_height - 1; i++) {
        leaf_idx1 >>= 1;
        leaf_idx2 >>= 1;
        leaf_idx3 >>= 1;
        leaf_idx4 >>= 1;
        idx_offset1 >>= 1;
        idx_offset2 >>= 1;
        idx_offset3 >>= 1;
        idx_offset4 >>= 1;

        /* Set the address of the node we're creating. */
        set_tree_height(addr, i + 1);
        set_tree_height(addr+8, i + 1);
        set_tree_height(addr+16, i + 1);
        set_tree_height(addr+24, i + 1);
        set_tree_index(addr,    leaf_idx1 + idx_offset1);
        set_tree_index(addr+8,  leaf_idx2 + idx_offset2);
        set_tree_index(addr+16, leaf_idx3 + idx_offset3);
        set_tree_index(addr+24, leaf_idx4 + idx_offset4);

        /* Pick the right or left neighbor, depending on parity of the node. */
        if (leaf_idx1 & 1) {
            out1 = buffer1 + SPX_N;
            oth1 = buffer1;
        } else {
            out1 = buffer1;
            oth1 = buffer1 + SPX_N;
        }
        if (leaf_idx2 & 1) {
            out2 = buffer2 + SPX_N;
            oth2 = buffer2;
        } else {
            out2 = buffer2;
            oth2 = buffer2 + SPX_N;
        }
        if (leaf_idx3 & 1) {
            out3 = buffer3 + SPX_N;
            oth3 = buffer3;
        } else {
            out3 = buffer3;
            oth3 = buffer3 + SPX_N;
        }
        if (leaf_idx4 & 1) {
            out4 = buffer4 + SPX_N;
            oth4 = buffer4;
        } else {
            out4 = buffer4;
            oth4 = buffer4 + SPX_N;
        }
        thashx4(
            out1, out2, out3, out4,
            buffer1, buffer2, buffer3, buffer4,
            2, pub_seed, addr
        );
        memcpy(oth1, auth_path1, SPX_N);
        memcpy(oth2, auth_path2, SPX_N);
        memcpy(oth3, auth_path3, SPX_N);
        memcpy(oth4, auth_path4, SPX_N);

        auth_path1 += SPX_N;
        auth_path2 += SPX_N;
        auth_path3 += SPX_N;
        auth_path4 += SPX_N;
    }

    /* The last iteration is exceptional; we do not copy an auth_path node. */
    leaf_idx1 >>= 1;
    leaf_idx2 >>= 1;
    leaf_idx3 >>= 1;
    leaf_idx4 >>= 1;

    idx_offset1 >>= 1;
    idx_offset2 >>= 1;
    idx_offset3 >>= 1;
    idx_offset4 >>= 1;

    set_tree_height(addr,    tree_height);
    set_tree_height(addr+8,  tree_height);
    set_tree_height(addr+16, tree_height);
    set_tree_height(addr+24, tree_height);

    set_tree_index(addr,    leaf_idx1 + idx_offset1);
    set_tree_index(addr+8,  leaf_idx2 + idx_offset2);
    set_tree_index(addr+16, leaf_idx3 + idx_offset3);
    set_tree_index(addr+24, leaf_idx4 + idx_offset4);

    thashx4(
        root1, root2, root3, root4,
        buffer1, buffer2, buffer3, buffer4,
        2, pub_seed, addr
    );
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
    uint32_t indices[SPX_FORS_TREES+3];
    unsigned char roots[(SPX_FORS_TREES+3) * SPX_N];
    unsigned char leaf1[SPX_N], leaf2[SPX_N], leaf3[SPX_N], leaf4[SPX_N];
    const unsigned char *sig1, *sig2, *sig3, *sig4;
    uint32_t fors_tree_addr[4*8] = {0};
    uint32_t fors_pk_addr[8] = {0};
    uint32_t idx_offset1, idx_offset2, idx_offset3, idx_offset4;
    unsigned int i;

    copy_keypair_addr(fors_tree_addr, fors_addr);
    copy_keypair_addr(fors_tree_addr+8, fors_addr);
    copy_keypair_addr(fors_tree_addr+16, fors_addr);
    copy_keypair_addr(fors_tree_addr+24, fors_addr);

    copy_keypair_addr(fors_pk_addr, fors_addr);

    set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
    set_type(fors_tree_addr+8, SPX_ADDR_TYPE_FORSTREE);
    set_type(fors_tree_addr+16, SPX_ADDR_TYPE_FORSTREE);
    set_type(fors_tree_addr+24, SPX_ADDR_TYPE_FORSTREE);

    set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices(indices, m);

    for (i = 0; i < SPX_FORS_TREES; i += 4) {
        idx_offset1 = i * (1 << SPX_FORS_HEIGHT);
        idx_offset2 = (i+1) * (1 << SPX_FORS_HEIGHT);
        idx_offset3 = (i+2) * (1 << SPX_FORS_HEIGHT);
        idx_offset4 = (i+3) * (1 << SPX_FORS_HEIGHT);

        set_tree_height(fors_tree_addr, 0);
        set_tree_height(fors_tree_addr + 8, 0);
        set_tree_height(fors_tree_addr + 16, 0);
        set_tree_height(fors_tree_addr + 24, 0);
        set_tree_index(fors_tree_addr, indices[i] + idx_offset1);
        set_tree_index(fors_tree_addr + 8, indices[i+1] + idx_offset2);
        set_tree_index(fors_tree_addr + 16, indices[i+2] + idx_offset3);
        set_tree_index(fors_tree_addr + 24, indices[i+3] + idx_offset4);

        sig1 = sig;
        sig += SPX_N*(SPX_FORS_HEIGHT+1);
        sig2 = sig;
        sig += SPX_N*(SPX_FORS_HEIGHT+1);
        sig3 = sig;
        sig += SPX_N*(SPX_FORS_HEIGHT+1);
        sig4 = sig;
        sig += SPX_N*(SPX_FORS_HEIGHT+1);

        if (i + 3 == SPX_FORS_TREES)
            sig4 = sig1;
        else if (i + 2 == SPX_FORS_TREES)
            sig3 = sig1;
        else if (i + 1 == SPX_FORS_TREES)
            sig2 = sig1; // XXX use scalar functions in this case.

        /* Derive the leaf from the included secret key part. */
        fors_sk_to_leafx4(
            leaf1, leaf2, leaf3, leaf4,
            sig1, sig2, sig3, sig4,
            pub_seed, fors_tree_addr
        );
        sig1 += SPX_N;
        sig2 += SPX_N;
        sig3 += SPX_N;
        sig4 += SPX_N;

        compute_rootx4(
            roots + i*SPX_N, roots + (i+1)*SPX_N, roots + (i+2)*SPX_N, roots + (i+3)*SPX_N,
            leaf1, leaf2, leaf3, leaf4,
            indices[i], indices[i+1], indices[i+2], indices[i+3],
            idx_offset1, idx_offset2, idx_offset3, idx_offset4,
            sig1, sig2, sig3, sig4,
            SPX_FORS_HEIGHT, pub_seed, fors_tree_addr
        );
    }

    /* Hash horizontally across all tree roots to derive the public key. */
    thash(pk, roots, SPX_FORS_TREES, pub_seed, fors_pk_addr);
}
