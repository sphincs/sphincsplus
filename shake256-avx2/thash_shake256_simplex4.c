#include <stdint.h>
#include <string.h>
#include <immintrin.h>

#include "thashx4.h"
#include "f1600x4.h"
#include "address.h"
#include "params.h"


static uint32_t swap32(uint32_t val) {
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF );
    return (val << 16) | (val >> 16);
}


/**
 * 4-way parallel version of thash; takes 4x as much input and output
 */
void thashx4(unsigned char *out0,
             unsigned char *out1,
             unsigned char *out2,
             unsigned char *out3,
             const unsigned char *in0,
             const unsigned char *in1,
             const unsigned char *in2,
             const unsigned char *in3, unsigned int inblocks,
             const unsigned char *pub_seed, uint32_t addrx4[4*8])
{
    if (SPX_N <= 32 && (inblocks == 1 || inblocks == 2)) {
        /* As we write and read only a few quadwords, it is more efficient to
         * build and extract from the fourway SHAKE256 state by hand. */
        __m256i state[25];
        for (int i = 0; i < SPX_N/8; i++) {
            state[i] = _mm256_set1_epi64x(((int64_t*)pub_seed)[i]);
        }
        for (int i = 0; i < 4; i++) {
            state[SPX_N/8+i] = _mm256_set_epi32(
                swap32(addrx4[3*8+1+2*i]),
                swap32(addrx4[3*8+2*i]),
                swap32(addrx4[2*8+1+2*i]),
                swap32(addrx4[2*8+2*i]),
                swap32(addrx4[8+1+2*i]),
                swap32(addrx4[8+2*i]),
                swap32(addrx4[1+2*i]),
                swap32(addrx4[2*i])
            );
        }

        for (unsigned int i = 0; i < (SPX_N/8) * inblocks; i++) {
            state[SPX_N/8+4+i] = _mm256_set_epi64x(
                        ((int64_t*)in3)[i],
                        ((int64_t*)in2)[i],
                        ((int64_t*)in1)[i],
                        ((int64_t*)in0)[i]
                    );
        }

        /* Domain separator and padding. */
        for (int i = (SPX_N/8)*(1+inblocks)+4; i < 16; i++) {
            state[i] = _mm256_set1_epi64x(0);
        }
        state[16] = _mm256_set1_epi64x(0x80ll << 56);
        state[(SPX_N/8)*(1+inblocks)+4] = _mm256_xor_si256(
            state[(SPX_N/8)*(1+inblocks)+4],
            _mm256_set1_epi64x(0x1f)
        );
        for (int i = 17; i < 25; i++) {
            state[i] = _mm256_set1_epi64x(0);
        }

        f1600x4AVX2((uint64_t*)&state[0], &keccak_rc[0]);

        for (int i = 0; i < SPX_N/8; i++) {
            ((int64_t*)out0)[i] = _mm256_extract_epi64(state[i], 0);
            ((int64_t*)out1)[i] = _mm256_extract_epi64(state[i], 1);
            ((int64_t*)out2)[i] = _mm256_extract_epi64(state[i], 2);
            ((int64_t*)out3)[i] = _mm256_extract_epi64(state[i], 3);
        }
    } else if (SPX_N == 64 && (inblocks == 1 || inblocks == 2)) {
        /* As we write and read only a few quadwords, it is more efficient to
         * build and extract from the fourway SHAKE256 state by hand. */
        __m256i state[25];
        for (int i = 0; i < 8; i++) {
            state[i] = _mm256_set1_epi64x(((int64_t*)pub_seed)[i]);
        }
        for (int i = 0; i < 4; i++) {
            state[8+i] = _mm256_set_epi32(
                swap32(addrx4[3*8+1+2*i]),
                swap32(addrx4[3*8+2*i]),
                swap32(addrx4[2*8+1+2*i]),
                swap32(addrx4[2*8+2*i]),
                swap32(addrx4[8+1+2*i]),
                swap32(addrx4[8+2*i]),
                swap32(addrx4[1+2*i]),
                swap32(addrx4[2*i])
            );
        }

        for (int i = 17; i < 25; i++) {
            state[i] = _mm256_set1_epi64x(0);
        }

        /* We will won't be able to fit all input in on go. */
        for (unsigned int i = 0; i < 5; i++) {
            state[8+4+i] = _mm256_set_epi64x(
                ((int64_t*)in3)[i],
                ((int64_t*)in2)[i],
                ((int64_t*)in1)[i],
                ((int64_t*)in0)[i]
            );
        }

        f1600x4AVX2((uint64_t*)&state[0], &keccak_rc[0]);

        /* Final input. */
        for (unsigned int i = 0; i < 3+8*(inblocks-1); i++) {
            state[i] = _mm256_xor_si256(
                state[i],
                _mm256_set_epi64x(
                    ((int64_t*)in3)[i+5],
                    ((int64_t*)in2)[i+5],
                    ((int64_t*)in1)[i+5],
                    ((int64_t*)in0)[i+5]
                )
            );
        }

        /* Domain separator and padding. */
        state[3+8*(inblocks-1)] = _mm256_xor_si256(state[3+8*(inblocks-1)],
                _mm256_set1_epi64x(0x1f));
        state[16] = _mm256_xor_si256(state[16], _mm256_set1_epi64x(0x80ll << 56));

        f1600x4AVX2((uint64_t*)&state[0], &keccak_rc[0]);

        for (int i = 0; i < 8; i++) {
            ((int64_t*)out0)[i] = _mm256_extract_epi64(state[i], 0);
            ((int64_t*)out1)[i] = _mm256_extract_epi64(state[i], 1);
            ((int64_t*)out2)[i] = _mm256_extract_epi64(state[i], 2);
            ((int64_t*)out3)[i] = _mm256_extract_epi64(state[i], 3);
        }
    } else {
        assert(0);
    }
}
