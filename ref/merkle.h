#if !defined( MERKLE_H_ )
#define MERKLE_H_

#include <stdint.h>

/* Generate a Merkle signature (WOTS signature followed by the Merkle */
/* authentication path) */
void merkle_sign(uint8_t *sig, unsigned char *root,
        const unsigned char *sk_seed, const unsigned char *pub_seed,
        uint32_t wots_addr[8], uint32_t tree_addr[8],
        uint32_t idx_leaf);

/* Compute the root node of the top-most subtree. */
void merkle_gen_root(unsigned char *root,
        const unsigned char *sk_seed, const unsigned char *pub_seed);

#endif /* MERKLE_H_ */
