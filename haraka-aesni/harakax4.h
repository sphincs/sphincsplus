#ifndef SPX_HARAKAX4_H
#define SPX_HARAKAX4_H

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

/* Applies the 512-bit Haraka permutation x4 to in. */
void haraka512_perm_x4(unsigned char *out, const unsigned char *in);

/* Implementation of Haraka-512 x4*/
void haraka512x4(unsigned char *out, const unsigned char *in);

/* Implementation of Haraka-256 x4 */
void haraka256x4(unsigned char *out, const unsigned char *in);

/* Implementation of Haraka-256 x4 using sk.seed constants */
void haraka256_skx4(unsigned char *out, const unsigned char *in);

#endif
