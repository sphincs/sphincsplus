#ifndef SPX_WOTS_H
#define SPX_WOTS_H

#include <stdint.h>
#include "params.h"

/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 *
 * Writes the computed public key to 'pk'.
 */
void wots_pk_from_sig(unsigned char *pk,
                      const unsigned char *sig, const unsigned char *msg,
                      const unsigned char *pub_seed, uint32_t addr[8]);

/*
 * Compute the chain lengths needed for a given message hash
 */
void chain_lengths(unsigned int *lengths, const unsigned char *msg);

#endif
