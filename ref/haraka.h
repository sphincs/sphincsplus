#ifndef SPX_HARAKA_H
#define SPX_HARAKA_H

/* Tweak constants with seed */
void tweak_constants(const unsigned char *pk_seed, const unsigned char *sk_seed, 
	                 unsigned long long seed_length);

/* Haraka Sponge */
void haraka_S(unsigned char *out, unsigned long long outlen,
              const unsigned char *in, unsigned long long inlen);

/* Haraka Sponge */
void haraka_Sx4(unsigned char *out0,
                unsigned char *out1,
                unsigned char *out2,
                unsigned char *out3, 
                unsigned long long outlen,
                const unsigned char *in0,
                const unsigned char *in1,
                const unsigned char *in2,
                const unsigned char *in3, 
                unsigned long long inlen);

/* Applies the 512-bit Haraka permutation to in. */
void haraka512_perm(unsigned char *out, const unsigned char *in);

/* Applies the 512-bit Haraka permutation x4 to in. */
void haraka512_perm_x4(unsigned char *out, const unsigned char *in);

/* Implementation of Haraka-512 */
void haraka512(unsigned char *out, const unsigned char *in);

/* Implementation of Haraka-512 x4*/
void haraka512x4(unsigned char *out, const unsigned char *in);

/* Implementation of Haraka-256 */
void haraka256(unsigned char *out, const unsigned char *in);

/* Implementation of Haraka-256 x4 */
void haraka256x4(unsigned char *out, const unsigned char *in);

/* Implementation of Haraka-256 using sk.seed constants */
void haraka256_sk(unsigned char *out, const unsigned char *in);

/* Implementation of Haraka-256 x4 using sk.seed constants */
void haraka256_skx4(unsigned char *out, const unsigned char *in);

#endif
