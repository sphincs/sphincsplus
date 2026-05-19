#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../api.h"

#define MLEN 32
#define NVECTORS 100

int main(void) {
    unsigned int i, j;
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t sig[CRYPTO_BYTES];
    uint8_t m[MLEN];
    unsigned long long siglen;

    printf("SPHINCS+ Test Vectors\n");
    printf("Public Key bytes = %d\n", CRYPTO_PUBLICKEYBYTES);
    printf("Secret Key bytes = %d\n", CRYPTO_SECRETKEYBYTES);
    printf("Signature bytes = %d\n", CRYPTO_BYTES);
    printf("\n");

    for(i = 0; i < NVECTORS; ++i) {
        printf("count = %u\n", i);

        // Generate random message
        for(j = 0; j < MLEN; ++j) {
            m[j] = (uint8_t)(rand() & 0xFF);
        }
        printf("m = ");
        for(j = 0; j < MLEN; ++j)
            printf("%02x", m[j]);
        printf("\n");

        // Key generation
        crypto_sign_keypair(pk, sk);
        printf("pk = ");
        for(j = 0; j < CRYPTO_PUBLICKEYBYTES; ++j)
            printf("%02x", pk[j]);
        printf("\n");
        printf("sk = ");
        for(j = 0; j < CRYPTO_SECRETKEYBYTES; ++j)
            printf("%02x", sk[j]);
        printf("\n");

        // Signing
        crypto_sign_signature(sig, &siglen, m, MLEN, sk);
        printf("sig = ");
        for(j = 0; j < siglen; ++j)
            printf("%02x", sig[j]);
        printf("\n");

        // Verification
        int valid = crypto_sign_verify(sig, siglen, m, MLEN, pk);
        printf("valid = %d\n", valid == 0 ? 1 : 0);

        if (valid == 0) {
            printf("PASS\n");
        } else {
            printf("FAIL\n");
        }
        printf("\n");
    }

    return 0;
}