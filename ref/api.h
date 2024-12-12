/*
 * SPDX-License-Identifier: NIST-Software
 * Copyright: National Institute of Standards and Technology; The software developed by NIST employees is not subject to copyright protection within the United States.
 *
NIST-developed software is provided by NIST as a public service. You may use, copy, and distribute copies of the software in any medium, provided that you keep intact this entire notice. You may improve, modify, and create derivative works of the software or any portion of the software, and you may copy and distribute such modifications or works. Modified works should carry a notice stating that you changed the software and should note the date and nature of any such change. Please explicitly acknowledge the National Institute of Standards and Technology as the source of the software.

NIST-developed software is expressly provided "AS IS." NIST MAKES NO WARRANTY OF ANY KIND, EXPRESS, IMPLIED, IN FACT, OR ARISING BY OPERATION OF LAW, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, AND DATA ACCURACY. NIST NEITHER REPRESENTS NOR WARRANTS THAT THE OPERATION OF THE SOFTWARE WILL BE UNINTERRUPTED OR ERROR-FREE, OR THAT ANY DEFECTS WILL BE CORRECTED. NIST DOES NOT WARRANT OR MAKE ANY REPRESENTATIONS REGARDING THE USE OF THE SOFTWARE OR THE RESULTS THEREOF, INCLUDING BUT NOT LIMITED TO THE CORRECTNESS, ACCURACY, RELIABILITY, OR USEFULNESS OF THE SOFTWARE.

You are solely responsible for determining the appropriateness of using and distributing the software and you assume all risks associated with its use, including but not limited to the risks and costs of program errors, compliance with applicable laws, damage to or loss of data, programs or equipment, and the unavailability or interruption of operation. This software is not intended to be used in any situation where a failure could cause risk of injury or damage to property. The software developed by NIST employees is not subject to copyright protection within the United States.
*/

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
 * Returns an array containing a detached signature.
 */
int crypto_sign_signature(uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen, const uint8_t *sk);

/**
 * Verifies a detached signature and message under a given public key.
 */
int crypto_sign_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen, const uint8_t *pk);

/**
 * Returns an array containing the signature followed by the message.
 */
int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen,
                const unsigned char *sk);

/**
 * Verifies a given signature-message pair under a given public key.
 */
int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk);

#endif
