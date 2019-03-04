#include <stdio.h>
#include <string.h>

#include "../thashx8.h"
#include "../thash.h"
#include "../randombytes.h"
#include "../params.h"

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

    randombytes(seed, SPX_N);
    randombytes(input, 8*SPX_N);
    randombytes((unsigned char *)addr, 8 * 8 * sizeof(uint32_t));

    printf("Testing if thash matches thashx8.. ");

    for (j = 0; j < 8; j++) {
        thash(out8 + j * SPX_N, input + j * SPX_N, 1, seed, addr + j*8);
    }

    thashx8(output + 0*SPX_N,
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
            1, seed, addr);

    if (memcmp(out8, output, 8 * SPX_N)) {
        printf("failed!\n");
        return -1;
    }
    printf("successful.\n");
    return 0;
}
