#include <stdio.h>
#include <string.h>

#include "../thashx4.h"
#include "../thash.h"
#include "../randombytes.h"
#include "../params.h"

int main(void)
{
    /* Make stdout buffer more responsive. */
    setbuf(stdout, NULL);

    unsigned char input[4*SPX_N];
    unsigned char output[4*SPX_N];
    unsigned char out4[4*SPX_N];
    uint32_t addr[4*8] = {0};
    unsigned int j;
    spx_ctx ctx;

    randombytes(ctx.pub_seed, SPX_N);
    randombytes(input, 4*SPX_N);
    randombytes((unsigned char *)addr, 4 * 8 * sizeof(uint32_t));

    printf("Testing if thash matches thashx4.. ");

    for (j = 0; j < 4; j++) {
        thash(out4 + j * SPX_N, input + j * SPX_N, 1, &ctx, addr + j*8);
    }

    thashx4(output + 0*SPX_N,
            output + 1*SPX_N,
            output + 2*SPX_N,
            output + 3*SPX_N,
            input + 0*SPX_N,
            input + 1*SPX_N,
            input + 2*SPX_N,
            input + 3*SPX_N,
            1, &ctx, addr);

    if (memcmp(out4, output, 4 * SPX_N)) {
        printf("failed!\n");
        return -1;
    }
    printf("successful.\n");
    return 0;
}
