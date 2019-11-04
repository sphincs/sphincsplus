#ifndef SPX_API_H
#define SPX_API_H

#include <stddef.h>
#include <stdint.h>

#include "params.h"

#define SPX_CRYPTO_ALGNAME "SPHINCS+"

#define SPX_CRYPTO_SECRETKEYBYTES  SPX_SK_BYTES
#define SPX_CRYPTO_PUBLICKEYBYTES  SPX_PK_BYTES
#define SPX_CRYPTO_BYTES           SPX_BYTES
#define SPX_CRYPTO_SEEDBYTES       SPX_N*3

#ifdef NIST_COMPATIBLE
// Define the non-namespaced NIST variants.
#define CRYPTO_ALGNAME          SPX_CRYPTO_ALGNAME
#define CRYPTO_BYTES            SPX_CRYPTO_BYTES
#define CRYPTO_PUBLICKEYBYTES   SPX_CRYPTO_PUBLICKEYBYTES
#define CRYPTO_SECRETKEYBYTES   SPX_CRYPTO_SECRETKEYBYTES
#define crypto_sign_keypair     SPX_crypto_sign_keypair
#define crypto_sign_signature   SPX_crypto_sign_signature
#define crypto_sign_verify      SPX_crypto_sign_signature
#define crypto_sign             SPX_crypto_sign
#define crypto_sign_open        SPX_crypto_sign_open
#endif

/*
 * Returns the length of a secret key, in bytes
 */
size_t SPX_crypto_sign_secretkeybytes(void);

/*
 * Returns the length of a public key, in bytes
 */
size_t SPX_crypto_sign_publickeybytes(void);

/*
 * Returns the length of a signature, in bytes
 */
size_t SPX_crypto_sign_bytes(void);

/*
 * Returns the length of the seed required to generate a key pair, in bytes
 */
size_t SPX_crypto_sign_seedbytes(void);

/*
 * Generates a SPHINCS+ key pair given a seed.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED]
 */
int SPX_crypto_sign_seed_keypair(
    uint8_t *pk, uint8_t *sk, const uint8_t *seed);

/*
 * Generates a SPHINCS+ key pair.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED]
 */
int SPX_crypto_sign_keypair(
    uint8_t *pk, uint8_t *sk);

/**
 * Returns an array containing a detached signature.
 */
int SPX_crypto_sign_signature(
    uint8_t *sig, size_t *siglen,
    const uint8_t *m, size_t mlen, const uint8_t *sk);

/**
 * Verifies a detached signature and message under a given public key.
 */
int SPX_crypto_sign_verify(
    const uint8_t *sig, size_t siglen,
    const uint8_t *m, size_t mlen, const uint8_t *pk);

/**
 * Returns an array containing the signature followed by the message.
 */
int SPX_crypto_sign(
    uint8_t *sm, size_t *smlen,
    const uint8_t *m, size_t mlen, const uint8_t *sk);

/**
 * Verifies a given signature-message pair under a given public key.
 */
int SPX_crypto_sign_open(
    uint8_t *m, size_t *mlen,
    const uint8_t *sm, size_t smlen, const uint8_t *pk);

#endif
