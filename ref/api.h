#ifndef SPX_API_H
#define SPX_API_H

#include <stddef.h>
#include <stdint.h>

#include "params.h"

#define CRYPTO_ALGNAME "SPHINCS+"

#define CRYPTO_SECRETKEYBYTES SPX_SK_BYTES
#define CRYPTO_PUBLICKEYBYTES SPX_PK_BYTES
#define CRYPTO_BYTES SPX_BYTES
#define CRYPTO_SEEDBYTES 3*SPX_N

/*
 * Returns the length of a secret key, in bytes
 */
unsigned long long crypto_sign_secretkeybytes(void);

/*
 * Returns the length of a public key, in bytes
 */
unsigned long long crypto_sign_publickeybytes(void);

/*
 * Returns the length of a signature, in bytes
 */
unsigned long long crypto_sign_bytes(void);

/*
 * Returns the length of the seed required to generate a key pair, in bytes
 */
unsigned long long crypto_sign_seedbytes(void);

/*
 * Generates a SPHINCS+ key pair given a seed.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED]
 */
int crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
                             const unsigned char *seed);

/*
 * Generates a SPHINCS+ key pair.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED]
 */
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

/**
 * Returns an array containing a detached signature, with caller-supplied
 * context string `ctx` (up to 255 bytes; pass NULL/0 for empty). Returns -1
 * if ctxlen > 255.
 */
int crypto_sign_signature(uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen,
                          const uint8_t *ctx, size_t ctxlen,
                          const uint8_t *sk);

/**
 * Derandomised variant of crypto_sign_signature: the caller supplies SPX_N
 * bytes of additional randomness `addrnd` in place of the randombytes() draw
 * that crypto_sign_signature() does internally. Pass `addrnd == NULL` to
 * request FIPS-205 deterministic signing (Alg 22): PK.seed is used as
 * addrnd.
 */
int crypto_sign_signature_derand(uint8_t *sig, size_t *siglen,
                                 const uint8_t *m, size_t mlen,
                                 const uint8_t *ctx, size_t ctxlen,
                                 const uint8_t *sk,
                                 const uint8_t *addrnd);

/**
 * Internal core (FIPS-205 §10.2 slh_sign_internal): the caller supplies the
 * raw `pre` buffer (typically `0x00 || ctxlen || ctx` for pure signing, or
 * the HashSLH-DSA prefix) that should be absorbed before the message.
 * Pass `addrnd == NULL` for FIPS-205 deterministic signing (addrnd defaults
 * to PK.seed).
 */
int crypto_sign_signature_internal(uint8_t *sig, size_t *siglen,
                                   const uint8_t *m, size_t mlen,
                                   const uint8_t *pre, size_t prelen,
                                   const uint8_t *sk,
                                   const uint8_t *addrnd);

/**
 * Verifies a detached signature and message under a given public key.
 * Returns 0 on success, non-zero on failure (including ctxlen > 255).
 */
int crypto_sign_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen,
                       const uint8_t *ctx, size_t ctxlen,
                       const uint8_t *pk);

/**
 * Internal core (FIPS-205 §10.2 slh_verify_internal): like crypto_sign_verify
 * but the caller supplies the raw `pre` buffer.
 */
int crypto_sign_verify_internal(const uint8_t *sig, size_t siglen,
                                const uint8_t *m, size_t mlen,
                                const uint8_t *pre, size_t prelen,
                                const uint8_t *pk);

/**
 * HashSLH-DSA signing (FIPS-205 §10.2.2). Caller supplies the pre-hashed
 * message `phm` (length `phmlen`) and the DER-encoded OID of the pre-hash
 * function. Returns -1 if ctxlen > 255 or the assembled prefix is too long.
 */
int crypto_sign_signature_prehash(uint8_t *sig, size_t *siglen,
                                  const uint8_t *phm, size_t phmlen,
                                  const uint8_t *oid, size_t oidlen,
                                  const uint8_t *ctx, size_t ctxlen,
                                  const uint8_t *sk);

/**
 * Derandomised variant of crypto_sign_signature_prehash. Pass `addrnd == NULL`
 * for FIPS-205 deterministic signing (PK.seed used as addrnd).
 */
int crypto_sign_signature_prehash_derand(uint8_t *sig, size_t *siglen,
                                         const uint8_t *phm, size_t phmlen,
                                         const uint8_t *oid, size_t oidlen,
                                         const uint8_t *ctx, size_t ctxlen,
                                         const uint8_t *sk,
                                         const uint8_t *addrnd);

/**
 * HashSLH-DSA verification (FIPS-205 §10.2.2). Caller supplies the pre-hashed
 * message and the DER-encoded OID of the pre-hash function.
 */
int crypto_sign_verify_prehash(const uint8_t *sig, size_t siglen,
                               const uint8_t *phm, size_t phmlen,
                               const uint8_t *oid, size_t oidlen,
                               const uint8_t *ctx, size_t ctxlen,
                               const uint8_t *pk);

/**
 * Returns an array containing the signature followed by the message, with
 * an explicit context string (NULL/0 for empty).
 */
int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen,
                const unsigned char *ctx, size_t ctxlen,
                const unsigned char *sk);

/**
 * Verifies a given signature-message pair under a given public key.
 */
int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *ctx, size_t ctxlen,
                     const unsigned char *pk);

#endif
