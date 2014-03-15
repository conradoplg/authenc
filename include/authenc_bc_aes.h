#ifndef AUTHENC_BC_H
#define AUTHENC_BC_H

#include <stddef.h>

#include "authenc_conf.h"

/*============================================================================*/
/* Constant definitions                                                       */
/*============================================================================*/

#define BC_AES_BLOCK_LEN 16
#define BC_AES128_KEY_LEN 16
#define BC_MAX_KEY_LEN 32


/*============================================================================*/
/* Type definitions                                                           */
/*============================================================================*/

/**
 * AES context structure.
 */
typedef struct {
	authenc_align unsigned char iv[BC_AES_BLOCK_LEN];
	authenc_align unsigned char ekey[12 * 128];
	size_t key_len;
} bc_aes_ctx_st;

/**
 * Pointer to an AES context structure.
 */
typedef bc_aes_ctx_st *bc_aes_ctx_t;

/**
 * Pointer to an AES context structure automatically allocated in the stack.
 */
typedef bc_aes_ctx_st bc_aes_ctx_at[1];


/*============================================================================*/
/* Function prototypes                                                        */
/*============================================================================*/

/**
 * Sets the encryption key.
 *
 * After this call, the context becomes ready to carry encryption.
 *
 * @param[in,out] ctx		- the encryption context.
 * @param[in] key			- the key
 * @param[in] key_len		- the key length, in bytes.
 * @return					- AUTHENC_OK if successful
 * 							- AUTHENC_INVALID_PARAMETER if key length is not supported.
 */
errno_t bc_aes_enc_key(bc_aes_ctx_t ctx, unsigned char *key, size_t key_len);

/**
 * Sets the decryption key.
 *
 * After this call, the context becomes ready to carry decryption.
 *
 * @param[in,out] ctx		- the decryption context.
 * @param[in] key			- the key
 * @param[in] key_len		- the key length, in bytes.
 * @return					- AUTHENC_OK if successful
 * 							- AUTHENC_INVALID_PARAMETER if key length is not supported
 */
errno_t bc_aes_dec_key(bc_aes_ctx_t ctx, unsigned char *key, size_t key_len);

/**
 * Encrypts a block.
 *
 * Input and output blocks must be aligned and have BC_AES_BLOCK_LEN bytes.
 *
 * @param[in,out] ctx		- the encryption context.
 * @param[out] output		- the ciphertext generated.
 * @param[in] input			- the plaintext to encrypt.
 */
void bc_aes_enc(bc_aes_ctx_t ctx, unsigned char *output, unsigned char *input);

/**
 * Decrypts a block.
 *
 * Input and output blocks must be aligned and have BC_AES_BLOCK_LEN bytes.
 *
 * @param[in,out] ctx		- the encryption context.
 * @param[out] output		- the ciphertext generated.
 * @param[in] input			- the plaintext to encrypt.
 */
void bc_aes_dec(bc_aes_ctx_t ctx, unsigned char *output, unsigned char *input);

#endif
