#include <stdint.h>
#include <string.h>

#include "utils.h"
#include "hash.h"
#include "hashx4.h"
#include "thash.h"
#include "thashx4.h"
#include "wots.h"
#include "address.h"
#include "params.h"

// TODO clarify address expectations, and make them more uniform.
// TODO i.e. do we expect types to be set already?
// TODO and do we expect modifications or copies?

/**
 * Computes the starting value for a chain, i.e. the secret key.
 * Expects the address to be complete up to the chain address.
 */
static void wots_gen_sk(unsigned char *sk, const unsigned char *sk_seed,
                        uint32_t wots_addr[8])
{
    /* Make sure that the hash address is actually zeroed. */
    set_hash_addr(wots_addr, 0);

    /* Generate sk element. */
    prf_addr(sk, sk_seed, wots_addr);
}

/**
 * 4-way parallel version of wots_gen_sk; expects 4x as much space in sk
 */
static void wots_gen_skx4(unsigned char *skx4, const unsigned char *sk_seed,
                          uint32_t wots_addrx4[4*8])
{
    unsigned int j;

    /* Make sure that the hash address is actually zeroed. */
    for (j = 0; j < 4; j++) {
        set_hash_addr(wots_addrx4 + j*8, 0);
    }

    /* Generate sk element. */
    prf_addrx4(skx4 + 0*SPX_N,
               skx4 + 1*SPX_N,
               skx4 + 2*SPX_N,
               skx4 + 3*SPX_N,
               sk_seed, wots_addrx4);
}

/**
 * Computes up the chains
 */
static void gen_chains(
        unsigned char *out,
        const unsigned char *in,
        unsigned int start[SPX_WOTS_LEN],
        unsigned int steps[SPX_WOTS_LEN],
        const unsigned char *pub_seed,
        uint32_t addr[8])
{
    uint32_t i, j, k, idx, watching;
    int done;
    unsigned char empty[SPX_N];
    unsigned char *bufs[4];
    uint32_t addrs[8*4];

    int l;
    uint16_t counts[SPX_WOTS_W] = { 0 };
    uint16_t idxs[SPX_WOTS_LEN];
    uint16_t total, newTotal;

    /* set addrs = {addr, addr, addr, addr} */
    for (j = 0; j < 4; j++) {
        memcpy(addrs+j*8, addr, sizeof(uint32_t) * 8);
    }

    /* Initialize out with the value at position 'start'. */
    memcpy(out, in, SPX_WOTS_LEN*SPX_N);

    /* Sort the chains in reverse order by steps using counting sort. */
    for (i = 0; i < SPX_WOTS_LEN; i++) {
        counts[steps[i]]++;
    }
    total = 0;
    for (l = SPX_WOTS_W - 1; l >= 0; l--) {
        newTotal = counts[l] + total;
        counts[l] = total;
        total = newTotal;
    }
    for (i = 0; i < SPX_WOTS_LEN; i++) {
        idxs[counts[steps[i]]] = i;
        counts[steps[i]]++;
    }

    /* We got our work cut out for us: do it! */
    for (i = 0; i < SPX_WOTS_LEN; i += 4) {
        for (j = 0; j < 4 && i+j < SPX_WOTS_LEN; j++) {
            idx = idxs[i+j];
            set_chain_addr(addrs+j*8, idx);
            bufs[j] = out + SPX_N * idx;
        }

        /* As the chains are sorted in reverse order, we know that the first
         * chain is the longest and the last one is the shortest.  We keep
         * an eye on whether the last chain is done and then on the one before,
         * et cetera. */
        watching = 3;
        done = 0;
        while (i + watching >= SPX_WOTS_LEN) {
            bufs[watching] = &empty[0];
            watching--;
        }

        for (k = 0;; k++) {
            while (k == steps[idxs[i+watching]]) {
                bufs[watching] = &empty[0];
                if (watching == 0) {
                    done = 1;
                    break;
                }
                watching--;
            }
            if (done) {
                break;
            }
            for (j = 0; j < watching + 1; j++) {
                set_hash_addr(addrs+j*8, k + start[idxs[i+j]]);
            }

            thashx4(bufs[0], bufs[1], bufs[2], bufs[3],
                    bufs[0], bufs[1], bufs[2], bufs[3], 1, pub_seed, addrs);
        }
    }
}


/**
 * 4-way parallel version of gen_chain; expects 4x as much space in out, and
 * 4x as much space in inx4. Assumes start and step identical across chains.
 */
static void gen_chainx4(unsigned char *outx4, const unsigned char *inx4,
                        unsigned int start, unsigned int steps,
                        const unsigned char *pub_seed, uint32_t addrx4[4*8])
{
    uint32_t i;
    unsigned int j;

    /* Initialize outx4 with the value at position 'start'. */
    memcpy(outx4, inx4, 4*SPX_N);

    /* Iterate 'steps' calls to the hash function. */
    for (i = start; i < (start+steps) && i < SPX_WOTS_W; i++) {
        for (j = 0; j < 4; j++) {
            set_hash_addr(addrx4 + j*8, i);
        }
        thashx4(outx4 + 0*SPX_N,
                outx4 + 1*SPX_N,
                outx4 + 2*SPX_N,
                outx4 + 3*SPX_N,
                outx4 + 0*SPX_N,
                outx4 + 1*SPX_N,
                outx4 + 2*SPX_N,
                outx4 + 3*SPX_N, 1, pub_seed, addrx4);
    }
}

/**
 * base_w algorithm as described in draft.
 * Interprets an array of bytes as integers in base w.
 * This only works when log_w is a divisor of 8.
 */
static void base_w(unsigned int *output, const int out_len,
                   const unsigned char *input)
{
    int in = 0;
    int out = 0;
    unsigned char total;
    int bits = 0;
    int consumed;

    for (consumed = 0; consumed < out_len; consumed++) {
        if (bits == 0) {
            total = input[in];
            in++;
            bits += 8;
        }
        bits -= SPX_WOTS_LOGW;
        output[out] = (total >> bits) & (SPX_WOTS_W - 1);
        out++;
    }
}

/* Computes the WOTS+ checksum over a message (in base_w). */
static void wots_checksum(unsigned int *csum_base_w,
                          const unsigned int *msg_base_w)
{
    unsigned int csum = 0;
    unsigned char csum_bytes[(SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8];
    unsigned int i;

    /* Compute checksum. */
    for (i = 0; i < SPX_WOTS_LEN1; i++) {
        csum += SPX_WOTS_W - 1 - msg_base_w[i];
    }

    /* Convert checksum to base_w. */
    /* Make sure expected empty zero bits are the least significant bits. */
    csum = csum << ((8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8)) % 8);
    ull_to_bytes(csum_bytes, sizeof(csum_bytes), csum);
    base_w(csum_base_w, SPX_WOTS_LEN2, csum_bytes);
}

/* Takes a message and derives the matching chain lengths. */
static void chain_lengths(unsigned int *lengths, const unsigned char *msg)
{
    base_w(lengths, SPX_WOTS_LEN1, msg);
    wots_checksum(lengths + SPX_WOTS_LEN1, lengths);
}

/**
 * WOTS key generation. Takes a 32 byte sk_seed, expands it to WOTS private key
 * elements and computes the corresponding public key.
 * It requires the seed pub_seed (used to generate bitmasks and hash keys)
 * and the address of this WOTS key pair.
 *
 * Writes the computed public key to 'pk'.
 */
void wots_gen_pk(unsigned char *pk, const unsigned char *sk_seed,
                 const unsigned char *pub_seed, uint32_t addr[8])
{
    uint32_t i;
    unsigned int j;

    uint32_t addrx4[4 * 8];
    unsigned char pkbuf[4 * SPX_N];

    for (j = 0; j < 4; j++) {
        memcpy(addrx4 + j*8, addr, sizeof(uint32_t) * 8);
    }

    /* The last iteration typically does not have complete set of 4 chains,
       but because we use pkbuf, this is not an issue -- we still do as many
       in parallel as possible. */
    for (i = 0; i < ((SPX_WOTS_LEN + 3) & ~0x3); i += 4) {
        for (j = 0; j < 4; j++) {
            set_chain_addr(addrx4 + j*8, i + j);
        }
        wots_gen_skx4(pkbuf, sk_seed, addrx4);
        gen_chainx4(pkbuf, pkbuf, 0, SPX_WOTS_W - 1, pub_seed, addrx4);
        for (j = 0; j < 4; j++) {
            if (i + j < SPX_WOTS_LEN) {
                memcpy(pk + (i + j)*SPX_N, pkbuf + j*SPX_N, SPX_N);
            }
        }
    }
}

/**
 * Takes a n-byte message and the 32-byte sk_see to compute a signature 'sig'.
 */
void wots_sign(unsigned char *sig, const unsigned char *msg,
               const unsigned char *sk_seed, const unsigned char *pub_seed,
               uint32_t addr[8])
{
    unsigned int steps[SPX_WOTS_LEN];
    unsigned int start[SPX_WOTS_LEN];
    uint32_t i;

    for (i = 0; i < SPX_WOTS_LEN; i++) {
        start[i] = 0;
        set_chain_addr(addr, i);
        wots_gen_sk(sig + i*SPX_N, sk_seed, addr);
    }

    chain_lengths(steps, msg);
    gen_chains(sig, sig, start, steps, pub_seed, addr);
}

/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 *
 * Writes the computed public key to 'pk'.
 */
void wots_pk_from_sig(unsigned char *pk,
                      const unsigned char *sig, const unsigned char *msg,
                      const unsigned char *pub_seed, uint32_t addr[8])
{
    unsigned int steps[SPX_WOTS_LEN];
    unsigned int start[SPX_WOTS_LEN];
    uint32_t i;

    chain_lengths(start, msg);

    for (i = 0; i < SPX_WOTS_LEN; i++) {
        steps[i] = SPX_WOTS_W - 1 - start[i];
    }

    gen_chains(pk, sig, start, steps, pub_seed, addr);
}
