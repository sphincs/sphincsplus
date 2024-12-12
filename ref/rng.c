/*
 * SPDX-License-Identifier: NIST-Software
 * Copyright: National Institute of Standards and Technology; The software developed by NIST employees is not subject to copyright protection within the United States.
 *
NIST-developed software is provided by NIST as a public service. You may use, copy, and distribute copies of the software in any medium, provided that you keep intact this entire notice. You may improve, modify, and create derivative works of the software or any portion of the software, and you may copy and distribute such modifications or works. Modified works should carry a notice stating that you changed the software and should note the date and nature of any such change. Please explicitly acknowledge the National Institute of Standards and Technology as the source of the software.

NIST-developed software is expressly provided "AS IS." NIST MAKES NO WARRANTY OF ANY KIND, EXPRESS, IMPLIED, IN FACT, OR ARISING BY OPERATION OF LAW, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, AND DATA ACCURACY. NIST NEITHER REPRESENTS NOR WARRANTS THAT THE OPERATION OF THE SOFTWARE WILL BE UNINTERRUPTED OR ERROR-FREE, OR THAT ANY DEFECTS WILL BE CORRECTED. NIST DOES NOT WARRANT OR MAKE ANY REPRESENTATIONS REGARDING THE USE OF THE SOFTWARE OR THE RESULTS THEREOF, INCLUDING BUT NOT LIMITED TO THE CORRECTNESS, ACCURACY, RELIABILITY, OR USEFULNESS OF THE SOFTWARE.

You are solely responsible for determining the appropriateness of using and distributing the software and you assume all risks associated with its use, including but not limited to the risks and costs of program errors, compliance with applicable laws, damage to or loss of data, programs or equipment, and the unavailability or interruption of operation. This software is not intended to be used in any situation where a failure could cause risk of injury or damage to property. The software developed by NIST employees is not subject to copyright protection within the United States.
*/

#include <string.h>
#include "rng.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

AES256_CTR_DRBG_struct  DRBG_ctx;

void    AES256_ECB(unsigned char *key, unsigned char *ctr, unsigned char *buffer);

/*
 seedexpander_init()
 ctx            - stores the current state of an instance of the seed expander
 seed           - a 32 byte random value
 diversifier    - an 8 byte diversifier
 maxlen         - maximum number of bytes (less than 2**32) generated under this seed and diversifier
 */
int
seedexpander_init(AES_XOF_struct *ctx,
                  unsigned char *seed,
                  unsigned char *diversifier,
                  unsigned long maxlen)
{
    if ( maxlen >= 0x100000000 )
        return RNG_BAD_MAXLEN;
    
    ctx->length_remaining = maxlen;
    
    memcpy(ctx->key, seed, 32);
    
    memcpy(ctx->ctr, diversifier, 8);
    ctx->ctr[11] = (unsigned char)(maxlen % 256);
    maxlen >>= 8;
    ctx->ctr[10] = (unsigned char)(maxlen % 256);
    maxlen >>= 8;
    ctx->ctr[9] = (unsigned char)(maxlen % 256);
    maxlen >>= 8;
    ctx->ctr[8] = (unsigned char)(maxlen % 256);
    memset(ctx->ctr+12, 0x00, 4);
    
    ctx->buffer_pos = 16;
    memset(ctx->buffer, 0x00, 16);
    
    return RNG_SUCCESS;
}

/*
 seedexpander()
    ctx  - stores the current state of an instance of the seed expander
    x    - returns the XOF data
    xlen - number of bytes to return
 */
int
seedexpander(AES_XOF_struct *ctx, unsigned char *x, unsigned long xlen)
{
    unsigned long   offset;
    
    if ( x == NULL )
        return RNG_BAD_OUTBUF;
    if ( xlen >= ctx->length_remaining )
        return RNG_BAD_REQ_LEN;
    
    ctx->length_remaining -= xlen;
    
    offset = 0;
    while ( xlen > 0 ) {
        if ( xlen <= (16-ctx->buffer_pos) ) { // buffer has what we need
            memcpy(x+offset, ctx->buffer+ctx->buffer_pos, xlen);
            ctx->buffer_pos += xlen;
            
            return RNG_SUCCESS;
        }
        
        // take what's in the buffer
        memcpy(x+offset, ctx->buffer+ctx->buffer_pos, 16-ctx->buffer_pos);
        xlen -= 16-ctx->buffer_pos;
        offset += 16-ctx->buffer_pos;
        
        AES256_ECB(ctx->key, ctx->ctr, ctx->buffer);
        ctx->buffer_pos = 0;
        
        //increment the counter
        for (int i=15; i>=12; i--) {
            if ( ctx->ctr[i] == 0xff )
                ctx->ctr[i] = 0x00;
            else {
                ctx->ctr[i]++;
                break;
            }
        }
        
    }
    
    return RNG_SUCCESS;
}


static void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

// Use whatever AES implementation you have. This uses AES from openSSL library
//    key - 256-bit AES key
//    ctr - a 128-bit plaintext value
//    buffer - a 128-bit ciphertext value
void
AES256_ECB(unsigned char *key, unsigned char *ctr, unsigned char *buffer)
{
    EVP_CIPHER_CTX *ctx;
    
    int len;
    
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
    
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL))
        handleErrors();
    
    if(1 != EVP_EncryptUpdate(ctx, buffer, &len, ctr, 16))
        handleErrors();
    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
}

void
randombytes_init(unsigned char *entropy_input,
                 unsigned char *personalization_string)
{
    unsigned char   seed_material[48];
    
    memcpy(seed_material, entropy_input, 48);
    if (personalization_string)
        for (int i=0; i<48; i++)
            seed_material[i] ^= personalization_string[i];
    memset(DRBG_ctx.Key, 0x00, 32);
    memset(DRBG_ctx.V, 0x00, 16);
    AES256_CTR_DRBG_Update(seed_material, DRBG_ctx.Key, DRBG_ctx.V);
    DRBG_ctx.reseed_counter = 1;
}

int
randombytes(unsigned char *x, unsigned long long xlen)
{
    unsigned char   block[16];
    int             i = 0;
    
    while ( xlen > 0 ) {
        //increment V
        for (int j=15; j>=0; j--) {
            if ( DRBG_ctx.V[j] == 0xff )
                DRBG_ctx.V[j] = 0x00;
            else {
                DRBG_ctx.V[j]++;
                break;
            }
        }
        AES256_ECB(DRBG_ctx.Key, DRBG_ctx.V, block);
        if ( xlen > 15 ) {
            memcpy(x+i, block, 16);
            i += 16;
            xlen -= 16;
        }
        else {
            memcpy(x+i, block, xlen);
            xlen = 0;
        }
    }
    AES256_CTR_DRBG_Update(NULL, DRBG_ctx.Key, DRBG_ctx.V);
    DRBG_ctx.reseed_counter++;
    
    return RNG_SUCCESS;
}

void
AES256_CTR_DRBG_Update(unsigned char *provided_data,
                       unsigned char *Key,
                       unsigned char *V)
{
    unsigned char   temp[48];
    
    for (int i=0; i<3; i++) {
        //increment V
        for (int j=15; j>=0; j--) {
            if ( V[j] == 0xff )
                V[j] = 0x00;
            else {
                V[j]++;
                break;
            }
        }
        
        AES256_ECB(Key, V, temp+16*i);
    }
    if ( provided_data != NULL )
        for (int i=0; i<48; i++)
            temp[i] ^= provided_data[i];
    memcpy(Key, temp, 32);
    memcpy(V, temp+32, 16);
}









