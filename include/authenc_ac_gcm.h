#ifndef AUTHENC_AC_H
#define AUTHENC_AC_H

#include <stddef.h>
#include <stdint.h>

#include "authenc_conf.h"
#include "authenc_sc_aesctr.h"

/*============================================================================*/
/* Constant definitions                                                       */
/*============================================================================*/

#define AC_GCM_TAG_LEN 16
#define AC_GCM_BLOCK_LEN BC_AES_BLOCK_LEN
#define AC_GCM_IV_LEN 12

/*============================================================================*/
/* Type definitions                                                           */
/*============================================================================*/

/**
 * Represents the context of the GCM encryption / decryption process.
 */
typedef struct {
	authenc_align unsigned char last_y[AC_GCM_BLOCK_LEN];
	authenc_align unsigned char ctr[AC_GCM_BLOCK_LEN];
	uint64_t len_a;
	uint64_t len_c;
	authenc_align dig_t table[32 * (AC_GCM_BLOCK_LEN / sizeof(dig_t) + 1)];
	sc_aesctr_ctx_at bc_ctx;
} ac_gcm_ctx_st;

/**
 * Pointer to a GCM context.
 */
typedef ac_gcm_ctx_st *ac_gcm_ctx_t;

/**
 * Pointer to a GCM context automatically allocated in the stack.
 */
typedef ac_gcm_ctx_st ac_gcm_ctx_at[1];

/*============================================================================*/
/* Function prototypes                                                        */
/*============================================================================*/

/**
 * Sets the authenticated encryption / decryption key.
 *
 * @param[out] ctx			- the context.
 * @param[in] key			- the key.
 * @param[in] key_len		- the length of the key in bytes.
 */
errno_t ac_gcm_key(ac_gcm_ctx_t ctx, const unsigned char *key, size_t key_len);

/**
 * Encrypt and authenticate data.
 *
 * @param[in] ctx				- the context.
 * @param[out] output			- the buffer where the encrypted and authenticated data will be written.
 * @param[in,out] output_len 	- input: the length of the buffer. Output: the length of the data written to @p output.
 * @param[in] input				- the data to encrypt and authenticate.
 * @param[in] input_len			- the length of the input.
 * @param[in] data				- additional data to authenticated, but not encrypt.
 * @param[in] data_len			- the length of data.
 * @param[in] iv				- the initialization vector. For GCM, must be nonce; MUST NOT be repeated for the same key.
 * 								  The IV must be sent along with the encrypted/authenticated data, or implicitly computed.
 * @param[in] iv_len			- the length of the initialization vector.
 * @return
 */
errno_t ac_gcm_enc(ac_gcm_ctx_t ctx, unsigned char *output, size_t *output_len, size_t output_capacity,
		const unsigned char *input, size_t input_len, const unsigned char *data,
		size_t data_len, const unsigned char *iv, size_t iv_len);

/**
 * Decrypt and verify data.
 *
 * @param[out] ctx				- the context.
 * @param[out] output			- the buffer where the decrypted and authenticated data will be written.
 * @param[in,out] output_len 	- input: the length of the buffer. Output: the length of the data written to @p output.
 * @param[in] input				- the data to encrypt and authenticate.
 * @param[in] input_len			- the length of the input.
 * @param[in] data				- the additional data to authenticate, but not encrypt.
 * @param[in] data_len			- the length of data.
 * @param[in] iv				- the same initialization vector used in encryption.
 * @param[in] iv_len			- the length of the initialization vector.
 * @return
 */
errno_t ac_gcm_dec(ac_gcm_ctx_t ctx, unsigned char *output, size_t *output_len, size_t output_capacity,
		const unsigned char *input, size_t input_len, const unsigned char *data,
		size_t data_len, const unsigned char *iv, size_t iv_len);

#endif /* AUTHENC_AC_H_ */
