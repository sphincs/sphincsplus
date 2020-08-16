#include <stdint.h>
#include <string.h>

#include "address.h"
#include "params.h"
#include "fips202x4.h"
#include "hashx4.h"

extern void KeccakP1600times4_PermuteAll_24rounds(__m256i *s);

/*
 * 4-way parallel version of prf_addr; takes 4x as much input and output
 */
void prf_addrx4(unsigned char *out0,
                unsigned char *out1,
                unsigned char *out2,
                unsigned char *out3,
                const unsigned char *key,
                const uint32_t addrx4[4*8]) {
    /* As we write and read only a few quadwords, it is more efficient to
     * build and extract from the fourway SHAKE256 state by hand. */
    __m256i state[25];
    
    for (int i = 0; i < SPX_N/8; i++) {
        state[i] = _mm256_set1_epi64x(((int64_t*)key)[i]);
    }
    for (int i = 0; i < 4; i++) {
        state[SPX_N/8+i] = _mm256_set_epi32(
            addrx4[3*8+1+2*i],
            addrx4[3*8+2*i],
            addrx4[2*8+1+2*i],
            addrx4[2*8+2*i],
            addrx4[8+1+2*i],
            addrx4[8+2*i],
            addrx4[1+2*i],
            addrx4[2*i]
        );
    }

    /* SHAKE domain separator and padding. */
    state[SPX_N/8+4] = _mm256_set1_epi64x(0x1f);
    for (int i = SPX_N/8+5; i < 16; i++) {
        state[i] = _mm256_set1_epi64x(0);
    }
    state[16] = _mm256_set1_epi64x(0x80ll << 56); 

    for (int i = 17; i < 25; i++) {
        state[i] = _mm256_set1_epi64x(0);
    }

    KeccakP1600times4_PermuteAll_24rounds(&state[0]);

    for (int i = 0; i < SPX_N/8; i++) {
        ((int64_t*)out0)[i] = _mm256_extract_epi64(state[i], 0);
        ((int64_t*)out1)[i] = _mm256_extract_epi64(state[i], 1);
        ((int64_t*)out2)[i] = _mm256_extract_epi64(state[i], 2);
        ((int64_t*)out3)[i] = _mm256_extract_epi64(state[i], 3);
    }
}
