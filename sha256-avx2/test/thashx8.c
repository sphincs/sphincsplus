#include <stdio.h>
#include <string.h>

#include "../hash.h"
#include "../hash_state.h"
#include "../hashx8.h"
#include "../params.h"
#include "../randombytes.h"
#include "../thash.h"
#include "../thashx8.h"


int main()
{
    /* Make stdout buffer more responsive. */
    setbuf(stdout, NULL);

    unsigned char input[8*SPX_N];
    unsigned char seed[SPX_N];
    unsigned char output[8*SPX_N];
    unsigned char out8[8*SPX_N];
    uint32_t addr[8*8] = {0};
    unsigned int j;
    hash_state state_seeded;

    randombytes(seed, SPX_N);
    randombytes(input, 8*SPX_N);
    randombytes((unsigned char *)addr, 8 * 8 * sizeof(uint32_t));

    SPX_initialize_hash_function(&state_seeded, seed, seed);

    printf("Testing if thash matches thashx8.. ");

    for (j = 0; j < 8; j++) {
        SPX_thash_1(out8 + j * SPX_N, input + j * SPX_N, seed, addr + j*8, &state_seeded);
    }

    SPX_thashx8_1(output + 0*SPX_N,
            output + 1*SPX_N,
            output + 2*SPX_N,
            output + 3*SPX_N,
            output + 4*SPX_N,
            output + 5*SPX_N,
            output + 6*SPX_N,
            output + 7*SPX_N,
            input + 0*SPX_N,
            input + 1*SPX_N,
            input + 2*SPX_N,
            input + 3*SPX_N,
            input + 4*SPX_N,
            input + 5*SPX_N,
            input + 6*SPX_N,
            input + 7*SPX_N,
            seed, addr, &state_seeded);

    if (memcmp(out8, output, 8 * SPX_N)) {
        printf("failed!\n");
        return -1;
    }
    printf("successful.\n");
    return 0;
}
