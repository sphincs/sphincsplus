#include <stdio.h>
#include <string.h>

#include "../randombytes.h"
#include "../params.h"
#include "../hash_state.h"
#include "../hash.h"
#include "../hashx8.h"
#include "../sha256x8.h"

int main()
{
    /* Make stdout buffer more responsive. */
    setbuf(stdout, NULL);

    unsigned char key[SPX_N];
    unsigned char seed[SPX_N];
    unsigned char output[8*SPX_N];
    unsigned char out8[8*SPX_N];
    uint32_t addr[8*8] = {0};
    unsigned int j;
    hash_state state_seeded;

    randombytes(seed, SPX_N);
    randombytes(key, SPX_N);
    randombytes((unsigned char *)addr, 8 * 8 * sizeof(uint32_t));

    SPX_initialize_hash_function(&state_seeded, seed, seed);

    printf("Testing if prf_addr matches prf_addrx8.. ");

    for (j = 0; j < 8; j++) {
        SPX_prf_addr(
            out8 + j * SPX_N,
            key,
            addr + j*8,
            &state_seeded);
    }

    SPX_prf_addrx8(
            output + 0*SPX_N,
            output + 1*SPX_N,
            output + 2*SPX_N,
            output + 3*SPX_N,
            output + 4*SPX_N,
            output + 5*SPX_N,
            output + 6*SPX_N,
            output + 7*SPX_N,
            key,
            addr);

    if (memcmp(out8, output, 8 * SPX_N)) {
        printf("failed!\n");
        return -1;
    }
    printf("successful.\n");
    return 0;
}
