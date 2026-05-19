#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../api.h"

#define CLIENT_SK_PATH "client_sk.bin"
#define CLIENT_PK_PATH "client_pk.bin"
#define SERVER_PK_PATH "server_pk.bin"

static int write_file(const char *path, const uint8_t *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) {
        return -1;
    }
    if (fwrite(buf, 1, len, f) != len) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

int main(void) {
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];

    printf("[*] Generating SPHINCS+ keypair...\n");
    if (crypto_sign_keypair(pk, sk) != 0) {
        fprintf(stderr, "Key generation failed\n");
        return 1;
    }

    if (write_file(CLIENT_SK_PATH, sk, sizeof(sk)) < 0) {
        fprintf(stderr, "Failed to write %s\n", CLIENT_SK_PATH);
        return 1;
    }

    if (write_file(CLIENT_PK_PATH, pk, sizeof(pk)) < 0) {
        fprintf(stderr, "Failed to write %s\n", CLIENT_PK_PATH);
        return 1;
    }

    if (write_file(SERVER_PK_PATH, pk, sizeof(pk)) < 0) {
        fprintf(stderr, "Failed to write %s\n", SERVER_PK_PATH);
        return 1;
    }

    printf("[OK] Wrote %s, %s, %s\n", CLIENT_SK_PATH, CLIENT_PK_PATH, SERVER_PK_PATH);
    printf("Copy %s to the server machine before running the server.\n", SERVER_PK_PATH);
    return 0;
}