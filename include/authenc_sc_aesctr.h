#ifndef AUTHENC_SC_AESCTR_H_
#define AUTHENC_SC_AESCTR_H_

#include "authenc_bc_aes.h"

/*============================================================================*/
/* Constant definitions                                                       */
/*============================================================================*/

#define SC_AES128CTR_KEY_LEN 16
#define SC_AESCTR_BLOCK_LEN BC_AES_BLOCK_LEN
#define SC_AESCTR_IV_LEN SC_AESCTR_BLOCK_LEN

/*============================================================================*/
/* Type definitions                                                           */
/*============================================================================*/

/**
 * Represents the context of the AES-CTR encryption / decryption process.
 */
typedef struct {
	bc_aes_ctx_at aes_ctx;
} sc_aesctr_ctx_st;

/**
 * Pointer to a GCM context.
 */
typedef sc_aesctr_ctx_st *sc_aesctr_ctx_t;

/**
 * Pointer to a GCM context automatically allocated in the stack.
 */
typedef sc_aesctr_ctx_st sc_aesctr_ctx_at[1];

/**
 * Sets the encryption / decryption key.
 *
 * @param[out] ctx			- the context.
 * @param[in] key			- the key.
 * @param[in] key_len		- the length of the key in bytes.
 */
errno_t sc_aesctr_key(sc_aesctr_ctx_t ctx, unsigned char *key, size_t key_len);

errno_t sc_aesctr_enc(sc_aesctr_ctx_t ctx, unsigned char *output,
		const unsigned char *input, size_t input_len,
		const unsigned char *nonce, size_t nonce_len);

#endif /* AUTHENC_SC_AESCTR_H_ */
