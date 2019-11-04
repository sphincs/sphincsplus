#include <stdio.h>
#include <string.h>

#include "../hash.h"
#include "../wots.h"
#include "../randombytes.h"
#include "../params.h"

int main()
{
    /* Make stdout buffer more responsive. */
    setbuf(stdout, NULL);

    uint8_t seed[SPX_N];
    uint8_t pub_seed[SPX_N];
    uint8_t pk1[SPX_WOTS_PK_BYTES];
    uint8_t pk2[SPX_WOTS_PK_BYTES];
    uint8_t sig[SPX_WOTS_BYTES];
    uint8_t m[SPX_N];
    uint32_t addr[8] = {0};

    randombytes(seed, SPX_N);
    randombytes(pub_seed, SPX_N);
    randombytes(m, SPX_N);
    randombytes((unsigned char *)addr, 8 * sizeof(uint32_t));

    printf("Testing WOTS signature and PK derivation.. ");

    hash_state state;
    SPX_initialize_hash_function(&state, pub_seed, seed);

    SPX_wots_gen_pk(pk1, seed, pub_seed, addr, &state);
    SPX_wots_sign(sig, m, seed, pub_seed, addr, &state);
    SPX_wots_pk_from_sig(pk2, sig, m, pub_seed, addr, &state);

    if (memcmp(pk1, pk2, SPX_WOTS_PK_BYTES)) {
        printf("failed!\n");
        return -1;
    }
    printf("successful.\n");
    return 0;
}
