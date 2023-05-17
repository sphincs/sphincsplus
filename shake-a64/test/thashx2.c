#include <stdio.h>
#include <string.h>

#include "../thashx2.h"
#include "../thash.h"
#include "../randombytes.h"
#include "../params.h"

int main(void)
{
    /* Make stdout buffer more responsive. */
    setbuf(stdout, NULL);

    unsigned char input[2*SPX_N];
    unsigned char output[2*SPX_N];
    unsigned char out2[2*SPX_N];
    uint32_t addr[2*8] = {0};
    unsigned int j;
    spx_ctx ctx;

    randombytes(ctx.pub_seed, SPX_N);
    randombytes(input, 4*SPX_N);
    randombytes((unsigned char *)addr, 2 * 8 * sizeof(uint32_t));

    printf("Testing if thash matches thashx2.. ");

    for (j = 0; j < 2; j++) {
        thash(out2 + j * SPX_N, input + j * SPX_N, 1, &ctx, addr + j*8);
    }

    thashx2(output + 0*SPX_N,
            output + 1*SPX_N,
            input + 0*SPX_N,
            input + 1*SPX_N,
            1, &ctx, addr);

    if (memcmp(out2, output, 2 * SPX_N)) {
        printf("failed!\n");
        return -1;
    }
    printf("successful.\n");
    return 0;
}
