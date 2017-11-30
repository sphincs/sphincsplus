#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "../api.h"
#include "../params.h"
#include "../randombytes.h"

#define SPX_MLEN 32

static unsigned long long cpucycles(void)
{
  unsigned long long result;
  __asm volatile(".byte 15;.byte 49;shlq $32,%%rdx;orq %%rdx,%%rax"
    : "=a" (result) ::  "%rdx");
  return result;
}

int main()
{
    /* Make stdout buffer more responsive. */
    setbuf(stdout, NULL);

    unsigned char pk[SPX_PK_BYTES];
    unsigned char sk[SPX_SK_BYTES];
    unsigned char *m = malloc(SPX_MLEN);
    unsigned char *sm = malloc(SPX_BYTES + SPX_MLEN);
    unsigned char *mout = malloc(SPX_BYTES + SPX_MLEN);
    unsigned long long smlen;
    unsigned long long mlen;
    unsigned long long t0, t1;
    struct timespec start, stop;
    double result;

    randombytes(m, SPX_MLEN);

    printf("Parameters: n = %d, h = %d, d = %d, b = %d, k = %d, w = %d\n",
           SPX_N, SPX_FULL_HEIGHT, SPX_D, SPX_FORS_HEIGHT, SPX_FORS_TREES,
           SPX_WOTS_W);

    printf("Generating keypair.. ");

    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
    t0 = cpucycles();
    crypto_sign_keypair(pk, sk);
    t1 = cpucycles();
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stop);
    result = (stop.tv_sec - start.tv_sec) * 1e6 + (stop.tv_nsec - start.tv_nsec) / 1e3;
    printf("took %lf us (%.2lf sec), %llu cycles\n", result, result / 1e6, t1 - t0);

    printf("Signing.. ");

    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
    t0 = cpucycles();
    crypto_sign(sm, &smlen, m, SPX_MLEN, sk);
    t1 = cpucycles();
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stop);
    result = (stop.tv_sec - start.tv_sec) * 1e6 + (stop.tv_nsec - start.tv_nsec) / 1e3;
    printf("took %lf us (%.2lf sec), %llu cycles\n", result, result / 1e6, t1 - t0);

    printf("Verifying.. ");
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
    t0 = cpucycles();
    crypto_sign_open(mout, &mlen, sm, smlen, pk);
    t1 = cpucycles();
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stop);
    result = (stop.tv_sec - start.tv_sec) * 1e6 + (stop.tv_nsec - start.tv_nsec) / 1e3;
    printf("took %lf us (%.2lf sec), %llu cycles\n", result, result / 1e6, t1 - t0);

    printf("Signature size: %d (%.2f KiB)\n", SPX_BYTES, SPX_BYTES / 1024.0);
    printf("Public key size: %d (%.2f KiB)\n", SPX_PK_BYTES, SPX_PK_BYTES / 1024.0);
    printf("Secret key size: %d (%.2f KiB)\n", SPX_SK_BYTES, SPX_SK_BYTES / 1024.0);

    free(m);
    free(sm);
    free(mout);

    return 0;
}