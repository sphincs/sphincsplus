#include <stdio.h>
#include <string.h>

#include "../thashx8.h"
#include "../thash.h"
#include "../randombytes.h"
#include "../params.h"
#include "../hash.h"

#if SPX_SHA512
#include "../sha2.h"
#include "../sha512x4.h"
#endif


int main(void)
{
    /* Make stdout buffer more responsive. */
    setbuf(stdout, NULL);

    unsigned char input[16*SPX_N];
    spx_ctx ctx;
    unsigned char output[8*SPX_N];
    unsigned char out8[8*SPX_N];
    uint32_t addr[8*8] = {0};
    unsigned int j;

    randombytes(ctx.pub_seed, SPX_N);
    randombytes(input, 16*SPX_N);
    randombytes((unsigned char *)addr, 8 * 8 * sizeof(uint32_t));

    initialize_hash_function(&ctx);

    printf("Testing if thash matches thashx8 on one block ... ");

    for (j = 0; j < 8; j++) {
        thash(out8 + j * SPX_N, input + j * SPX_N, 1, &ctx, addr + j*8);
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
            1, &ctx, addr);

    if (memcmp(out8, output, 8 * SPX_N)) {
        printf("failed!\n");
        return -1;
    }
    printf("successful.\n");

    printf("Testing if thash matches thashx8 on two blocks ... ");

    for (j = 0; j < 8; j++) {
        thash(out8 + j * SPX_N, input + (2*j) * SPX_N, 2, &ctx, addr + j*8);
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
            input + 2*SPX_N,
            input + 4*SPX_N,
            input + 6*SPX_N,
            input + 8*SPX_N,
            input + 10*SPX_N,
            input + 12*SPX_N,
            input + 14*SPX_N,
            2, &ctx, addr);

    if (memcmp(out8, output, 8 * SPX_N)) {
        printf("failed!\n");
        return -1;
    }
    printf("successful.\n");
    return 0;
}
