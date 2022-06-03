#include <stdio.h>
#include <string.h>

#include "../thashx8.h"
#include "../thash.h"
#include "../randombytes.h"
#include "../params.h"
#include "../hash.h"

#if SPX_SHA512
#include "../sha256.h"
#include "../sha512x4.h"
#endif


int main()
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

#if SPX_SHA512
    {
        uint8_t buf[SPX_SHA512_OUTPUT_BYTES];
        sha512ctx4x ctx4;
        __m256i bufx4[8];

        printf("Testing if (prefix of) sha512 matches sha512x4 ... ");

        for (j = 0; j < 4; j++) {
            sha512(buf, input + j*SPX_N, SPX_N);
            memcpy(out8 + j*SPX_N, buf, SPX_N);
        }

        sha512_init4x(&ctx4);
        sha512_update4x(
            &ctx4,
            input + 0*SPX_N,
            input + 1*SPX_N,
            input + 2*SPX_N,
            input + 3*SPX_N,
            SPX_N
        );
        sha512_final4x(
            &ctx4,
            bufx4 + 0,
            bufx4 + 2,
            bufx4 + 4,
            bufx4 + 6
        );

        for (j = 0; j < 4; j++) {
            memcpy(output + j*SPX_N, bufx4 + 2*j, SPX_N);
        }

        if (memcmp(out8, output, 4 * SPX_N)) {
            printf("failed!\n");
            return -1;
        }
        printf("successful.\n");
    }
#endif

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
