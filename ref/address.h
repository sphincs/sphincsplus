#ifndef SPX_ADDRESS_H
#define SPX_ADDRESS_H

#include <stdint.h>

#define SPX_ADDR_TYPE_WOTS 0
#define SPX_ADDR_TYPE_WOTSPK 1
#define SPX_ADDR_TYPE_HASHTREE 2
#define SPX_ADDR_TYPE_FORSTREE 3
#define SPX_ADDR_TYPE_FORSPK 4

void set_layer_addr(uint8_t addr[32], uint32_t layer);

void set_tree_addr(uint8_t addr[32], uint64_t tree);

void set_type(uint8_t addr[32], uint32_t type);

/* Copies the layer and tree part of one address into the other */
void copy_subtree_addr(uint8_t out[32], const uint8_t in[32]);

/* These functions are used for WOTS and FORS addresses. */

void set_keypair_addr(uint8_t addr[32], uint32_t keypair);

void set_chain_addr(uint8_t addr[32], uint32_t chain);

void set_hash_addr(uint8_t addr[32], uint32_t hash);

void copy_keypair_addr(uint8_t out[32], const uint8_t in[32]);

/* These functions are used for all hash tree addresses (including FORS). */

void set_tree_height(uint8_t addr[32], uint32_t tree_height);

void set_tree_index(uint8_t addr[21], uint32_t tree_index);

#endif
