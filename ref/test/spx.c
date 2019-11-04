#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../api.h"
#include "../params.h"
#include "../randombytes.h"

#define SPX_MLEN 32
#define SPX_SIGNATURES 1

int main()
{
    int ret = 0;
    int i;

    /* Make stdout buffer more responsive. */
    setbuf(stdout, NULL);

    uint8_t pk[SPX_PK_BYTES];
    uint8_t sk[SPX_SK_BYTES];
    uint8_t *m = malloc(SPX_MLEN);
    uint8_t *sm = malloc(SPX_BYTES + SPX_MLEN);
    uint8_t *mout = malloc(SPX_BYTES + SPX_MLEN);
    size_t smlen;
    size_t mlen;

    randombytes(m, SPX_MLEN);

    printf("Generating keypair.. ");

    if (SPX_crypto_sign_keypair(pk, sk)) {
        printf("failed!\n");
        ret = -1;
        goto end;
    }
    printf("successful.\n");

    printf("Testing %d signatures.. \n", SPX_SIGNATURES);

    for (i = 0; i < SPX_SIGNATURES; i++) {
        printf("  - iteration #%d:\n", i);

        SPX_crypto_sign(sm, &smlen, m, SPX_MLEN, sk);

        if (smlen != SPX_BYTES + SPX_MLEN) {
            printf("  X smlen incorrect [%zu != %u]!\n", smlen, SPX_BYTES);
            ret = -1;
        }
        else {
            printf("    smlen as expected [%zu].\n", smlen);
        }

        /* Test if signature is valid. */
        if (SPX_crypto_sign_open(mout, &mlen, sm, smlen, pk)) {
            printf("  X verification failed!\n");
            ret = -1;
        }
        else {
            printf("    verification succeeded.\n");
        }

        /* Test if the correct message was recovered. */
        if (mlen != SPX_MLEN) {
            printf("  X mlen incorrect [%zu != %u]!\n", mlen, SPX_MLEN);
            ret = -1;
        }
        else {
            printf("    mlen as expected [%zu].\n", mlen);
        }
        if (memcmp(m, mout, SPX_MLEN)) {
            printf("  X output message incorrect!\n");
            ret = -1;
        }
        else {
            printf("    output message as expected.\n");
        }

        /* Test if signature is valid when validating in-place. */
        if (SPX_crypto_sign_open(sm, &mlen, sm, smlen, pk)) {
            printf("  X in-place verification failed!\n");
            ret = -1;
        }
        else {
            printf("    in-place verification succeeded.\n");
        }

        /* Test if flipping bits invalidates the signature (it should). */

        /* Flip the first bit of the message. Should invalidate. */
        sm[smlen - 1] ^= 1;
        if (!SPX_crypto_sign_open(mout, &mlen, sm, smlen, pk)) {
            printf("  X flipping a bit of m DID NOT invalidate signature!\n");
            ret = -1;
        }
        else {
            printf("    flipping a bit of m invalidates signature.\n");
        }
        sm[smlen - 1] ^= 1;

#ifdef SPX_TEST_INVALIDSIG
        int j;
        /* Flip one bit per hash; the signature is entirely hashes. */
        for (j = 0; j < (int)(smlen - SPX_MLEN); j += SPX_N) {
            sm[j] ^= 1;
            if (!crypto_sign_open(mout, &mlen, sm, smlen, pk)) {
                printf("  X flipping bit %d DID NOT invalidate sig + m!\n", j);
                sm[j] ^= 1;
                ret = -1;
                break;
            }
            sm[j] ^= 1;
        }
        if (j >= (int)(smlen - SPX_MLEN)) {
            printf("    changing any signature hash invalidates signature.\n");
        }
#endif
    }

end:
    free(m);
    free(sm);
    free(mout);

    return ret;
}
