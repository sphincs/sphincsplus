#include <stdio.h>
#include <string.h>

#include "../randombytes.h"
#include "../params.h"
#include "../hash_state.h"
#include "../hash.h"
#include "../hashx4.h"
#include "../fips202x4.h"

int main()
{
    /* Make stdout buffer more responsive. */
    setbuf(stdout, NULL);

    unsigned char key[SPX_N];
    unsigned char seed[SPX_N];
    unsigned char output[4*SPX_N];
    unsigned char out4[4*SPX_N];
    uint32_t addr[4*8] = {0};
    unsigned int j;
    hash_state state_seeded;

    randombytes(seed, SPX_N);
    randombytes(key, SPX_N);
    randombytes((unsigned char *)addr, 4 * 8 * sizeof(uint32_t));

    printf("Testing if prf_addr matches prf_addrx4.. ");

    for (j = 0; j < 4; j++) {
        SPX_prf_addr(
            out4 + j * SPX_N,
            key,
            addr + j*8,
            &state_seeded);
    }

    SPX_prf_addrx4(
            output + 0*SPX_N,
            output + 1*SPX_N,
            output + 2*SPX_N,
            output + 3*SPX_N,
            key,
            addr);

    if (memcmp(out4, output, 4 * SPX_N)) {
        printf("failed!\n");
        return -1;
    }
    printf("successful.\n");
    return 0;
}
