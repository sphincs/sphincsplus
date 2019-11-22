#include <stdio.h>
#include <string.h>

#include "../hash.h"
#include "../fors.h"
#include "../randombytes.h"
#include "../params.h"

int main()
{
    /* Make stdout buffer more responsive. */
    setbuf(stdout, NULL);

    uint8_t sk_seed[SPX_N];
    uint8_t pub_seed[SPX_N];
    uint8_t pk1[SPX_FORS_PK_BYTES];
    uint8_t pk2[SPX_FORS_PK_BYTES];
    uint8_t sig[SPX_FORS_BYTES];
    uint8_t m[SPX_FORS_MSG_BYTES];
    uint32_t addr[8] = {0};

    randombytes(sk_seed, SPX_N);
    randombytes(pub_seed, SPX_N);
    randombytes(pk1, SPX_FORS_PK_BYTES);
    randombytes(pk2, SPX_FORS_PK_BYTES);
    randombytes(m, SPX_FORS_MSG_BYTES);
    randombytes((uint8_t *)addr, 8 * sizeof(uint32_t));

    printf("Testing FORS signature and PK derivation.. ");

    hash_state state;
    SPX_initialize_hash_function(&state, pub_seed, sk_seed);

    SPX_fors_sign(sig, pk1, m, sk_seed, pub_seed, addr, &state);
    SPX_fors_pk_from_sig(pk2, sig, m, pub_seed, addr, &state);

    if (memcmp(pk1, pk2, SPX_FORS_PK_BYTES)) {
        printf("failed!\n");
        return -1;
    }
    printf("successful.\n");
    return 0;
}
