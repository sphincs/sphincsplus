#include <stdint.h>
#include <string.h>

#include "address.h"
#include "utils.h"
#include "params.h"
#include "hash.h"
#include "sha2.h"

#if SPX_N >= 24
#define SPX_SHAX_OUTPUT_BYTES SPX_SHA512_OUTPUT_BYTES
#define SPX_SHAX_BLOCK_BYTES SPX_SHA512_BLOCK_BYTES
#define shaX_inc_init sha512_inc_init
#define shaX_inc_blocks sha512_inc_blocks
#define shaX_inc_finalize sha512_inc_finalize
#define shaX sha512
#define mgf1_X mgf1_512
#else
#define SPX_SHAX_OUTPUT_BYTES SPX_SHA256_OUTPUT_BYTES
#define SPX_SHAX_BLOCK_BYTES SPX_SHA256_BLOCK_BYTES
#define shaX_inc_init sha256_inc_init
#define shaX_inc_blocks sha256_inc_blocks
#define shaX_inc_finalize sha256_inc_finalize
#define shaX sha256
#define mgf1_X mgf1_256
#endif


/* For SHA, there is no immediate reason to initialize at the start,
   so this function is an empty operation. */
void initialize_hash_function(spx_ctx *ctx)
{
    seed_state(ctx);
}

/*
 * Computes PRF(pk_seed, sk_seed, addr).
 */
void prf_addr(unsigned char *out, const spx_ctx *ctx,
              const uint32_t addr[8])
{
    uint8_t sha2_state[40];
    unsigned char buf[SPX_SHA256_ADDR_BYTES + SPX_N];
    unsigned char outbuf[SPX_SHA256_OUTPUT_BYTES];

    /* Retrieve precomputed state containing pub_seed */
    memcpy(sha2_state, ctx->state_seeded, 40 * sizeof(uint8_t));

    /* Remainder: ADDR^c ‖ SK.seed */
    memcpy(buf, addr, SPX_SHA256_ADDR_BYTES);
    memcpy(buf + SPX_SHA256_ADDR_BYTES, ctx->sk_seed, SPX_N);

    sha256_inc_finalize(outbuf, sha2_state, buf, SPX_SHA256_ADDR_BYTES + SPX_N);

    memcpy(out, outbuf, SPX_N);
}

/*
 * Byte-granular incremental absorb on top of the block-granular SHA-X inc
 * API. A `shaX_buf` bundles the underlying SHA-X state with a sub-block
 * carry buffer so callers can feed any number of variable-length chunks
 * before finalising. Usage:
 *
 *     struct shaX_buf b;
 *     shaX_buf_init(&b);
 *     shaX_buf_absorb(&b, chunk1, len1);
 *     shaX_buf_absorb(&b, chunk2, len2);
 *     ...
 *     shaX_buf_finalize(out, &b, m, mlen);
 */
struct shaX_buf {
    uint8_t       state[8 + SPX_SHAX_OUTPUT_BYTES];
    unsigned char carry[SPX_SHAX_BLOCK_BYTES];
    size_t        carry_len;
};

static void shaX_buf_init(struct shaX_buf *b)
{
    shaX_inc_init(b->state);
    b->carry_len = 0;
}

static void shaX_buf_absorb(struct shaX_buf *b,
                            const unsigned char *in, size_t inlen)
{
    /* Top up the carry to a full block first, if it isn't empty. */
    if (b->carry_len) {
        size_t fill = SPX_SHAX_BLOCK_BYTES - b->carry_len;
        if (inlen < fill) {
            memcpy(b->carry + b->carry_len, in, inlen);
            b->carry_len += inlen;
            return;
        }
        memcpy(b->carry + b->carry_len, in, fill);
        shaX_inc_blocks(b->state, b->carry, 1);
        in    += fill;
        inlen -= fill;
        b->carry_len = 0;
    }

    /* Feed as many whole blocks as we can directly from the input. */
    size_t full = inlen / SPX_SHAX_BLOCK_BYTES;
    if (full) {
        shaX_inc_blocks(b->state, in, full);
        in    += full * SPX_SHAX_BLOCK_BYTES;
        inlen -= full * SPX_SHAX_BLOCK_BYTES;
    }

    /* Stash any sub-block tail in the carry. */
    if (inlen) {
        memcpy(b->carry, in, inlen);
        b->carry_len = inlen;
    }
}

static void shaX_buf_finalize(unsigned char *out, struct shaX_buf *b,
                              const unsigned char *m, unsigned long long mlen)
{
    shaX_buf_absorb(b, m, (size_t)mlen);
    shaX_inc_finalize(out, b->state, b->carry, b->carry_len);
}

/**
 * Computes the message-dependent randomness R, using a secret seed as a key
 * for HMAC, and an optional randomization value prefixed to the message.
 *
 * The `pre` buffer (length `prelen`) is absorbed between `optrand` and `m`;
 * it is used by the FIPS-205 external interfaces to inject the
 * domain-separator byte and context string.
 */
void gen_message_random(unsigned char *R, const unsigned char *sk_prf,
                        const unsigned char *optrand,
                        const unsigned char *pre, size_t prelen,
                        const unsigned char *m, unsigned long long mlen,
                        const spx_ctx *ctx)
{
    (void)ctx;

    unsigned char buf[SPX_SHAX_BLOCK_BYTES + SPX_SHAX_OUTPUT_BYTES];
    struct shaX_buf b;
    int i;

#if SPX_N > SPX_SHAX_BLOCK_BYTES
    #error "Currently only supports SPX_N of at most SPX_SHAX_BLOCK_BYTES"
#endif

    /* HMAC inner: H(ipad-keyed-block || optrand || pre || m). */
    for (i = 0; i < SPX_N; i++) {
        buf[i] = 0x36 ^ sk_prf[i];
    }
    memset(buf + SPX_N, 0x36, SPX_SHAX_BLOCK_BYTES - SPX_N);

    shaX_buf_init(&b);
    shaX_buf_absorb(&b, buf, SPX_SHAX_BLOCK_BYTES);
    shaX_buf_absorb(&b, optrand, SPX_N);
    if (prelen) {
        shaX_buf_absorb(&b, pre, prelen);
    }
    shaX_buf_finalize(buf + SPX_SHAX_BLOCK_BYTES, &b, m, mlen);

    /* HMAC outer: H(opad-keyed-block || inner-digest). */
    for (i = 0; i < SPX_N; i++) {
        buf[i] = 0x5c ^ sk_prf[i];
    }
    memset(buf + SPX_N, 0x5c, SPX_SHAX_BLOCK_BYTES - SPX_N);

    shaX(buf, buf, SPX_SHAX_BLOCK_BYTES + SPX_SHAX_OUTPUT_BYTES);
    memcpy(R, buf, SPX_N);
}

/**
 * Computes the message hash using R, the public key, and the message.
 * Outputs the message digest and the index of the leaf. The index is split in
 * the tree index and the leaf index, for convenient copying to an address.
 *
 * The `pre` buffer (length `prelen`) is absorbed between PK and `m`; it is
 * used by the FIPS-205 external interfaces to inject the domain-separator
 * byte and context string.
 */
void hash_message(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *pre, size_t prelen,
                  const unsigned char *m, unsigned long long mlen,
                  const spx_ctx *ctx)
{
    (void)ctx;
#define SPX_TREE_BITS (SPX_TREE_HEIGHT * (SPX_D - 1))
#define SPX_TREE_BYTES ((SPX_TREE_BITS + 7) / 8)
#define SPX_LEAF_BITS SPX_TREE_HEIGHT
#define SPX_LEAF_BYTES ((SPX_LEAF_BITS + 7) / 8)
#define SPX_DGST_BYTES (SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES)

    unsigned char seed[2*SPX_N + SPX_SHAX_OUTPUT_BYTES];

    unsigned char buf[SPX_DGST_BYTES];
    unsigned char *bufp = buf;
    struct shaX_buf b;

    shaX_buf_init(&b);

    /* seed: SHA-X(R ‖ PK.seed ‖ PK.root ‖ pre ‖ M) */
    shaX_buf_absorb(&b, R,  SPX_N);
    shaX_buf_absorb(&b, pk, SPX_PK_BYTES);
    if (prelen) {
        shaX_buf_absorb(&b, pre, prelen);
    }
    shaX_buf_finalize(seed + 2*SPX_N, &b, m, mlen);

    /* H_msg: MGF1-SHA-X(R ‖ PK.seed ‖ seed) */
    memcpy(seed, R, SPX_N);
    memcpy(seed + SPX_N, pk, SPX_N);

    /* By doing this in two steps, we prevent hashing the message twice;
       otherwise each iteration in MGF1 would hash the message again. */
    mgf1_X(bufp, SPX_DGST_BYTES, seed, 2*SPX_N + SPX_SHAX_OUTPUT_BYTES);

    memcpy(digest, bufp, SPX_FORS_MSG_BYTES);
    bufp += SPX_FORS_MSG_BYTES;

#if SPX_TREE_BITS > 64
    #error For given height and depth, 64 bits cannot represent all subtrees
#endif

    if (SPX_D == 1) {
	*tree = 0;
    } else {
        *tree = bytes_to_ull(bufp, SPX_TREE_BYTES);
        *tree &= (~(uint64_t)0) >> (64 - SPX_TREE_BITS);
    }
    bufp += SPX_TREE_BYTES;

    *leaf_idx = (uint32_t)bytes_to_ull(bufp, SPX_LEAF_BYTES);
    *leaf_idx &= (~(uint32_t)0) >> (32 - SPX_LEAF_BITS);
}


