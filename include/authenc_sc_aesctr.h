#ifndef AUTHENC_SC_AESCTR_H_
#define AUTHENC_SC_AESCTR_H_

#include "authenc_bc_aes.h"

/*============================================================================*/
/* Constant definitions                                                       */
/*============================================================================*/

/**
 * AES-128-CTR key length in bytes.
 */
#define SC_AES128CTR_KEY_LEN 16

/**
 * AES-CTR block length in bytes.
 */
#define SC_AESCTR_BLOCK_LEN BC_AES_BLOCK_LEN

/**
 * AES-CTR IV/nonce length in bytes.
 */
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
 * Pointer to a AES-CTR context.
 */
typedef sc_aesctr_ctx_st *sc_aesctr_ctx_t;

/**
 * Pointer to a AES-CTR context automatically allocated in the stack.
 */
typedef sc_aesctr_ctx_st sc_aesctr_ctx_at[1];

/*============================================================================*/
/* Function prototypes                                                        */
/*============================================================================*/

/**
 * Set the AES-CTR encryption / decryption key.
 *
 * @param[out] ctx			- the context.
 * @param[in] key			- the key.
 * @param[in] key_len		- the length of the key in bytes.
 */
errno_t sc_aesctr_key(sc_aesctr_ctx_t ctx, const unsigned char *key, size_t key_len);

/**
 * Encrypt data with AES-CTR.
 *
 * @param[in,out] ctx		- the context.
 * @param[out] output		- the output. Should have at least @p input_len bytes.
 * @param[in] input			- the input.
 * @param[in] input_len		- the length of the input in bytes.
 * @param[in] nonce			- the nonce.
 * @param[in] nonce_len		- the length of the nonce in bytes.
 * @return
 */
errno_t sc_aesctr_enc(sc_aesctr_ctx_t ctx, unsigned char *output,
		const unsigned char *input, size_t input_len,
		const unsigned char *nonce, size_t nonce_len);

#endif /* AUTHENC_SC_AESCTR_H_ */
