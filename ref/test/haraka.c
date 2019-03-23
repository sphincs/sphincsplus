#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

#include "../haraka.c"
#include "../randombytes.h"

static int test_haraka_S_incremental(void) {
    unsigned char input[521];
    unsigned char check[521];
    unsigned char output[521];
    uint8_t s_inc_absorb[65];
    uint8_t s_inc_squeeze[65];
    uint8_t s_inc_squeeze_all[65];
    uint8_t s_inc_both[65];
    uint8_t s_combined[64];
    int i;
    int absorbed;
    int squeezed;
    int returncode = 0;

    randombytes(input, 521);

    haraka_S(check, 521, input, 521);

    haraka_S_inc_init(s_inc_absorb);

    absorbed = 0;
    for (i = 0; i < 521 && absorbed + i <= 521; i++) {
        haraka_S_inc_absorb(s_inc_absorb, input + absorbed, i);
        absorbed += i;
    }
    haraka_S_inc_absorb(s_inc_absorb, input + absorbed, 521 - absorbed);

    haraka_S_inc_finalize(s_inc_absorb);

    memset(s_combined, 0, 64);
    haraka_S_absorb(s_combined, HARAKAS_RATE, input, 521, 0x1F);

    if (memcmp(s_inc_absorb, s_combined, 64 * sizeof(uint8_t))) {
        printf("ERROR haraka_S state after incremental absorb did not match all-at-once absorb.\n");
        printf("  Expected: ");
        for (i = 0; i < 64; i++) {
            printf("%02X", s_combined[i]);
        }
        printf("\n");
        printf("  State:    ");
        for (i = 0; i < 64; i++) {
            printf("%02X", s_inc_absorb[i]);
        }
        printf("\n");
        returncode = 1;
    }

    memcpy(s_inc_both, s_inc_absorb, 65 * sizeof(uint8_t));

    haraka_S_squeezeblocks(output, 3, s_inc_absorb, HARAKAS_RATE);

    if (memcmp(check, output, 3*HARAKAS_RATE)) {
        printf("ERROR haraka_S incremental absorb did not match haraka_S.\n");
        printf("  Expected: ");
        for (i = 0; i < 3*HARAKAS_RATE; i++) {
            printf("%02X", check[i]);
        }
        printf("\n");
        printf("  Received: ");
        for (i = 0; i < 3*HARAKAS_RATE; i++) {
            printf("%02X", output[i]);
        }
        printf("\n");
        returncode = 1;
    }

    memset(s_inc_squeeze, 0, 65);
    haraka_S_absorb(s_inc_squeeze, HARAKAS_RATE, input, 521, 0x1F);
    s_inc_squeeze[64] = 0;

    memcpy(s_inc_squeeze_all, s_inc_squeeze, 65 * sizeof(uint8_t));

    haraka_S_inc_squeeze(output, 521, s_inc_squeeze_all);

    if (memcmp(check, output, 521)) {
        printf("ERROR haraka_S incremental squeeze-all did not match haraka_S.\n");
        printf("  Expected: ");
        for (i = 0; i < 521; i++) {
            printf("%02X", check[i]);
        }
        printf("\n");
        printf("  Received: ");
        for (i = 0; i < 521; i++) {
            printf("%02X", output[i]);
        }
        printf("\n");
        returncode = 1;
    }

    squeezed = 0;
    memset(output, 0, 521);
    for (i = 0; i < 521 && squeezed + i <= 521; i++) {
        haraka_S_inc_squeeze(output + squeezed, i, s_inc_squeeze);
        squeezed += i;
    }
    haraka_S_inc_squeeze(output + squeezed, 521 - squeezed, s_inc_squeeze);

    if (memcmp(check, output, 521)) {
        printf("ERROR haraka_S incremental squeeze did not match haraka_S.\n");
        printf("  Expected: ");
        for (i = 0; i < 521; i++) {
            printf("%02X", check[i]);
        }
        printf("\n");
        printf("  Received: ");
        for (i = 0; i < 521; i++) {
            printf("%02X", output[i]);
        }
        printf("\n");
        returncode = 1;
    }

    squeezed = 0;
    memset(output, 0, 521);
    for (i = 0; i < 521 && squeezed + i <= 521; i++) {
        haraka_S_inc_squeeze(output + squeezed, i, s_inc_both);
        squeezed += i;
    }
    haraka_S_inc_squeeze(output + squeezed, 521 - squeezed, s_inc_both);

    if (memcmp(check, output, 521)) {
        printf("ERROR haraka_S incremental absorb + squeeze did not match haraka_S.\n");
        printf("  Expected: ");
        for (i = 0; i < 521; i++) {
            printf("%02X", check[i]);
        }
        printf("\n");
        printf("  Received: ");
        for (i = 0; i < 521; i++) {
            printf("%02X", output[i]);
        }
        printf("\n");
        returncode = 1;
    }

    return returncode;
}

int main(void) {
    int result = 0;
    result += test_haraka_S_incremental();

    if (result != 0) {
        puts("Errors occurred");
    }
    return result;
}
