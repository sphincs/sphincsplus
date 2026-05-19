#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#endif
#include "../api.h"

#define NTESTS 100

static uint64_t get_time_ns(void) {
#ifdef _WIN32
    static LARGE_INTEGER freq = {0};
    LARGE_INTEGER counter;

    if (freq.QuadPart == 0) {
        QueryPerformanceFrequency(&freq);
    }
    QueryPerformanceCounter(&counter);
    return (uint64_t)(counter.QuadPart * 1000000000ULL / freq.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}

static void print_results(const char *label, uint64_t *t, int ntests) {
    uint64_t min = UINT64_MAX;
    uint64_t max = 0;
    uint64_t sum = 0;

    for (int i = 0; i < ntests; i++) {
        if (t[i] < min) min = t[i];
        if (t[i] > max) max = t[i];
        sum += t[i];
    }

    double avg = (double)sum / ntests;
    printf("%s\n", label);
    printf("  Min: %llu ns\n", (unsigned long long)min);
    printf("  Max: %llu ns\n", (unsigned long long)max);
    printf("  Avg: %.2f ns\n", avg);
    printf("  Cycles per second: %.2f\n", 1000000000.0 / avg);
    printf("\n");
}

int main(void) {
    uint64_t t[NTESTS];
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t sig[CRYPTO_BYTES];
    uint8_t m[32] = {0}; // small message for speed test
    unsigned long long siglen;

    printf("SPHINCS+ Speed Test\n");
    printf("Public Key bytes = %d\n", CRYPTO_PUBLICKEYBYTES);
    printf("Secret Key bytes = %d\n", CRYPTO_SECRETKEYBYTES);
    printf("Signature bytes = %d\n", CRYPTO_BYTES);
    printf("Running %d tests...\n\n", NTESTS);

    // Key generation
    for (int i = 0; i < NTESTS; i++) {
        uint64_t start = get_time_ns();
        crypto_sign_keypair(pk, sk);
        uint64_t end = get_time_ns();
        t[i] = end - start;
    }
    print_results("Key Generation:", t, NTESTS);

    // Signing
    for (int i = 0; i < NTESTS; i++) {
        uint64_t start = get_time_ns();
        crypto_sign_signature(sig, &siglen, m, sizeof(m), sk);
        uint64_t end = get_time_ns();
        t[i] = end - start;
    }
    print_results("Signing:", t, NTESTS);

    // Verification
    for (int i = 0; i < NTESTS; i++) {
        uint64_t start = get_time_ns();
        int valid = crypto_sign_verify(sig, siglen, m, sizeof(m), pk);
        uint64_t end = get_time_ns();
        t[i] = end - start;
        (void)valid; // ignore result for speed test
    }
    print_results("Verification:", t, NTESTS);

    return 0;
}