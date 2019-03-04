#include <string.h>
#include <openssl/sha.h>

#include "sha256.h"
#include "utils.h"

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
