#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "../api.h"
#include "../fors.h"
#include "../wots.h"
#include "../wotsx4.h"
#include "../params.h"
#include "../randombytes.h"

#define SPX_MLEN 32
#define NTESTS 10

static void wots_gen_pkx4(unsigned char *pk, const spx_ctx *ctx,
        uint32_t addr[8]);

static int cmp_llu(const void *a, const void*b)
{
  if(*(unsigned long long *)a < *(unsigned long long *)b) return -1;
  if(*(unsigned long long *)a > *(unsigned long long *)b) return 1;
  return 0;
}

static unsigned long long median(unsigned long long *l, size_t llen)
{
  qsort(l,llen,sizeof(unsigned long long),cmp_llu);

  if(llen%2) return l[llen/2];
  else return (l[llen/2-1]+l[llen/2])/2;
}

static void delta(unsigned long long *l, size_t llen)
{
    unsigned int i;
    for(i = 0; i < llen - 1; i++) {
        l[i] = l[i+1] - l[i];
    }
}

static unsigned long long cpucycles(void)
{
  unsigned long long result;
  __asm volatile(".byte 15;.byte 49;shlq $32,%%rdx;orq %%rdx,%%rax"
    : "=a" (result) ::  "%rdx");
  return result;
}

static void printfcomma (unsigned long long n)
{
    if (n < 1000) {
        printf("%llu", n);
        return;
    }
    printfcomma(n / 1000);
    printf (",%03llu", n % 1000);
}

static void printfalignedcomma (unsigned long long n, int len)
{
    unsigned long long ncopy = n;
    int i = 0;

    while (ncopy > 9) {
        len -= 1;
        ncopy /= 10;
        i += 1;  // to account for commas
    }
    i = i/3 - 1;  // to account for commas
    for (; i < len; i++) {
        printf(" ");
    }
    printfcomma(n);
}

static void display_result(double result, unsigned long long *l, size_t llen, unsigned long long mul)
{
    unsigned long long med;

    result /= NTESTS;
    delta(l, NTESTS + 1);
    med = median(l, llen);
    printf("avg. %11.2lf us (%2.2lf sec); median ", result, result / 1e6);
    printfalignedcomma(med, 12);
    printf(" cycles,  %5llux: ", mul);
    printfalignedcomma(mul*med, 12);
    printf(" cycles\n");
}

#define MEASURE(TEXT, MUL, FNCALL)\
    printf(TEXT);\
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);\
    for(i = 0; i < NTESTS; i++) {\
        t[i] = cpucycles();\
        FNCALL;\
    }\
    t[NTESTS] = cpucycles();\
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stop);\
    result = (stop.tv_sec - start.tv_sec) * 1e6 + (stop.tv_nsec - start.tv_nsec) / 1e3;\
    display_result(result, t, NTESTS, MUL);

int main(void)
{
    /* Make stdout buffer more responsive. */
    setbuf(stdout, NULL);

    spx_ctx ctx;
    unsigned char pk[SPX_PK_BYTES];
    unsigned char sk[SPX_SK_BYTES];
    unsigned char *m = malloc(SPX_MLEN);
    unsigned char *sm = malloc(SPX_BYTES + SPX_MLEN);
    unsigned char *mout = malloc(SPX_BYTES + SPX_MLEN);

    unsigned char fors_pk[SPX_FORS_PK_BYTES];
    unsigned char fors_m[SPX_FORS_MSG_BYTES];
    unsigned char fors_sig[SPX_FORS_BYTES];
    unsigned char addr[SPX_ADDR_BYTES];
    unsigned char wots_pk[4*SPX_WOTS_PK_BYTES];

    unsigned long long smlen;
    unsigned long long mlen;
    unsigned long long t[NTESTS+1];
    struct timespec start, stop;
    double result;
    int i;

    randombytes(m, SPX_MLEN);
    randombytes(addr, SPX_ADDR_BYTES);

    printf("Parameters: n = %d, h = %d, d = %d, b = %d, k = %d, w = %d\n",
           SPX_N, SPX_FULL_HEIGHT, SPX_D, SPX_FORS_HEIGHT, SPX_FORS_TREES,
           SPX_WOTS_W);

    printf("Running %d iterations.\n", NTESTS);

    MEASURE("Generating keypair.. ", 1, crypto_sign_keypair(pk, sk));
    MEASURE("  - WOTS pk gen 4x.. ", (1 << SPX_TREE_HEIGHT) / 4, wots_gen_pkx4(wots_pk, &ctx, (uint32_t *) addr));
    MEASURE("Signing..            ", 1, crypto_sign(sm, &smlen, m, SPX_MLEN, sk));
    MEASURE("  - FORS signing..   ", 1, fors_sign(fors_sig, fors_pk, fors_m, &ctx, (uint32_t *) addr));
    MEASURE("  - WOTS pk gen x4.. ", SPX_D * (1 << SPX_TREE_HEIGHT) / 4, wots_gen_pkx4(wots_pk, &ctx, (uint32_t *) addr));
    MEASURE("Verifying..          ", 1, crypto_sign_open(mout, &mlen, sm, smlen, pk));

    printf("Signature size: %d (%.2f KiB)\n", SPX_BYTES, SPX_BYTES / 1024.0);
    printf("Public key size: %d (%.2f KiB)\n", SPX_PK_BYTES, SPX_PK_BYTES / 1024.0);
    printf("Secret key size: %d (%.2f KiB)\n", SPX_SK_BYTES, SPX_SK_BYTES / 1024.0);

    free(m);
    free(sm);
    free(mout);

    return 0;
}

static void wots_gen_pkx4(unsigned char *pk, const spx_ctx *ctx, uint32_t addr[8]) {
    struct leaf_info_x4 leaf;
    unsigned steps[ SPX_WOTS_LEN ] = { 0 };
    INITIALIZE_LEAF_INFO_X4(leaf, addr, steps);
    wots_gen_leafx4(pk, ctx, 0, &leaf);
}
