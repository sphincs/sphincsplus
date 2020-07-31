#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <immintrin.h>

#include "thashx4.h"
#include "address.h"
#include "params.h"

#include "f1600x4.h"


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

        /* SHAKE domain separator and padding */
        state[SPX_N/8+4] = _mm256_set1_epi64x(0x1f);
        for (int i = SPX_N/8+5; i < 16; i++) {
            state[i] = _mm256_set1_epi64x(0);
        }
        state[16] = _mm256_set1_epi64x(0x80ll << 56);

        for (int i = 17; i < 25; i++) {
            state[i] = _mm256_set1_epi64x(0);
        }

        /* We will permutate state2 with f1600x4 to compute the bitmask,
         * but first we'll copy it to state2 which will be used to compute
         * the final output, as its input is alsmost identical. */
        __m256i state2[25];
        memcpy(state2, state, 800);

        f1600x4AVX2((uint64_t*)&state[0], &keccak_rc[0]);

        /* By copying from state, state2 already contains the pub_seed
         * and addres.  We just need to copy in the input blocks xorred with
         * the bitmask we just computed. */
        for (unsigned int i = 0; i < (SPX_N/8) * inblocks; i++) {
            state2[SPX_N/8+4+i] = _mm256_xor_si256(
                    state[i],
                    _mm256_set_epi64x(
                        ((int64_t*)in3)[i],
                        ((int64_t*)in2)[i],
                        ((int64_t*)in1)[i],
                        ((int64_t*)in0)[i]
                    )
                );
        }

        /* Domain separator and start of padding.  Note that the quadwords
         * around are already zeroed for state from which we copied.
         * We do a XOR instead of a set as this might be the 16th quadword
         * when N=32 and inblocks=2, which already contains the end
         * of the padding. */
        state2[(SPX_N/8)*(1+inblocks)+4] = _mm256_xor_si256(
            state2[(SPX_N/8)*(1+inblocks)+4],
            _mm256_set1_epi64x(0x1f)
        );

        f1600x4AVX2((uint64_t*)&state2[0], &keccak_rc[0]);

        for (int i = 0; i < SPX_N/8; i++) {
            ((int64_t*)out0)[i] = _mm256_extract_epi64(state2[i], 0);
            ((int64_t*)out1)[i] = _mm256_extract_epi64(state2[i], 1);
            ((int64_t*)out2)[i] = _mm256_extract_epi64(state2[i], 2);
            ((int64_t*)out3)[i] = _mm256_extract_epi64(state2[i], 3);
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

        /* SHAKE domain separator and padding */
        state[8+4] = _mm256_set1_epi64x(0x1f);
        for (int i = 8+5; i < 16; i++) {
            state[i] = _mm256_set1_epi64x(0);
        }
        state[16] = _mm256_set1_epi64x(0x80ll << 56);

        for (int i = 17; i < 25; i++) {
            state[i] = _mm256_set1_epi64x(0);
        }

        /* We will permutate state2 with f1600x4 to compute the bitmask,
         * but first we'll copy it to state2 which will be used to compute
         * the final output, as its input is alsmost identical. */
        __m256i state2[25];
        memcpy(state2, state, 800);

        f1600x4AVX2((uint64_t*)&state[0], &keccak_rc[0]);

        /* We will won't be able to fit all input in on go.
         * By copying from state, state2 already contains the pub_seed
         * and addres.  We just need to copy in the input blocks xorred with
         * the bitmask we just computed. */
        for (unsigned int i = 0; i < 5; i++) {
            state2[8+4+i] = _mm256_xor_si256(
                    state[i],
                    _mm256_set_epi64x(
                        ((int64_t*)in3)[i],
                        ((int64_t*)in2)[i],
                        ((int64_t*)in1)[i],
                        ((int64_t*)in0)[i]
                    )
                );
        }

        f1600x4AVX2((uint64_t*)&state2[0], &keccak_rc[0]);

        /* Final input. */
        for (unsigned int i = 0; i < 3+8*(inblocks-1); i++) {
            state2[i] = _mm256_xor_si256(
                    state2[i],
                    _mm256_xor_si256(
                        state[i+5],
                        _mm256_set_epi64x(
                            ((int64_t*)in3)[i+5],
                            ((int64_t*)in2)[i+5],
                            ((int64_t*)in1)[i+5],
                            ((int64_t*)in0)[i+5]
                        )
                    )
                );
        }

        /* Domain separator and padding. */
        state2[3+8*(inblocks-1)] = _mm256_xor_si256(state2[3+8*(inblocks-1)],
                _mm256_set1_epi64x(0x1f));
        state2[16] = _mm256_xor_si256(state2[16], _mm256_set1_epi64x(0x80ll << 56));

        f1600x4AVX2((uint64_t*)&state2[0], &keccak_rc[0]);

        for (int i = 0; i < 8; i++) {
            ((int64_t*)out0)[i] = _mm256_extract_epi64(state2[i], 0);
            ((int64_t*)out1)[i] = _mm256_extract_epi64(state2[i], 1);
            ((int64_t*)out2)[i] = _mm256_extract_epi64(state2[i], 2);
            ((int64_t*)out3)[i] = _mm256_extract_epi64(state2[i], 3);
        }
    } else {
        assert(0);
    }
}
