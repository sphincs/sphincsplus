#include <string.h>
#include <openssl/sha.h>

#include "sha256.h"
#include "utils.h"

/*
 * Compresses an address to a 22-byte sequence.
 * This reduces the number of required SHA256 compression calls, as the last
 * block of input is padded with at least 65 bits.
 */
void compress_address(unsigned char *out, const uint32_t addr[8])
{
    ull_to_bytes(out,      1, addr[0]); /* drop 3 bytes of the layer field */
    ull_to_bytes(out + 1,  4, addr[2]); /* drop the highest tree address word */
    ull_to_bytes(out + 5,  4, addr[3]);
    ull_to_bytes(out + 9,  1, addr[4]); /* drop 3 bytes of the type field */
    ull_to_bytes(out + 10, 4, addr[5]);
    ull_to_bytes(out + 14, 4, addr[6]);
    ull_to_bytes(out + 18, 4, addr[7]);
}

/**
 * Note that inlen should be sufficiently small that it still allows for
 * an array to be allocated on the stack. Typically 'in' is merely a seed.
 * Outputs outlen number of bytes
 */
void mgf1(unsigned char *out, unsigned long outlen,
          const unsigned char *in, unsigned long inlen)
{
    unsigned char inbuf[inlen + 4];
    unsigned char outbuf[SPX_SHA256_OUTPUT_BYTES];
    unsigned long i;

    memcpy(inbuf, in, inlen);

    /* While we can fit in at least another full block of SHA256 output.. */
    for (i = 0; (i+1)*SPX_SHA256_OUTPUT_BYTES <= outlen; i++) {
        ull_to_bytes(inbuf + inlen, 4, i);
        SHA256(inbuf, inlen + 4, out);
        out += SPX_SHA256_OUTPUT_BYTES;
    }
    /* Until we cannot anymore, and we fill the remainder. */
    ull_to_bytes(inbuf + inlen, 4, i);
    SHA256(inbuf, inlen + 4, outbuf);
    memcpy(out, outbuf, outlen - i*SPX_SHA256_OUTPUT_BYTES);
}
