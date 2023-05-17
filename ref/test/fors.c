#include <stdio.h>
#include <string.h>

#include "../context.h"
#include "../hash.h"
#include "../fors.h"
#include "../randombytes.h"
#include "../params.h"

int main(void)
{
    /* Make stdout buffer more responsive. */
    setbuf(stdout, NULL);

    spx_ctx ctx;

    unsigned char pk1[SPX_FORS_PK_BYTES];
    unsigned char pk2[SPX_FORS_PK_BYTES];
    unsigned char sig[SPX_FORS_BYTES];
    unsigned char m[SPX_FORS_MSG_BYTES];
    uint32_t addr[8] = {0};

    randombytes(ctx.sk_seed, SPX_N);
    randombytes(ctx.pub_seed, SPX_N);
    randombytes(m, SPX_FORS_MSG_BYTES);
    randombytes((unsigned char *)addr, 8 * sizeof(uint32_t));

    printf("Testing FORS signature and PK derivation.. ");

    initialize_hash_function(&ctx);

    fors_sign(sig, pk1, m, &ctx, addr);
    fors_pk_from_sig(pk2, sig, m, &ctx, addr);

    if (memcmp(pk1, pk2, SPX_FORS_PK_BYTES)) {
        printf("failed!\n");
        return -1;
    }
    printf("successful.\n");
    return 0;
}
