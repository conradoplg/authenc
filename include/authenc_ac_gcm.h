#ifndef AUTHENC_AC_H
#define AUTHENC_AC_H

#include <stddef.h>
#include <stdint.h>

#include "authenc_conf.h"
#include "authenc_bc_aes.h"

/*============================================================================*/
/* Constant definitions                                                       */
/*============================================================================*/

#define AC_GCM_KEY_LEN 16
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
	uint64_t len_a;
	uint64_t len_c;
	dig_t table[32 * (AC_GCM_BLOCK_LEN / sizeof(dig_t) + 1)];
	bc_aes_ctx_at bc_ctx;
} ac_gcm_ctx_st;

/**
 * Pointer to a GCM context.
 */
typedef ac_gcm_ctx_st *ac_gcm_ctx_t;

/**
 * Pointer to a GCM context automatically allocated in the stack.
 */
typedef ac_gcm_ctx_st ac_gcm_ctx_at[1];

/**
 * Sets the authenticated encryption / decryption key.
 *
 * @param[out] ctx			- the context.
 * @param[in] key			- the key.
 * @param[in] key_len		- the length of the key in bytes.
 */
errno_t ac_gcm_key(ac_gcm_ctx_t ctx, unsigned char *key, size_t key_len);

/**
 * Initializes authenticated encryption / decryption with an initialization
 * vector, preparing to send a message.
 *
 * Some modes do not require the key; in that case, it can be NULL.
 * However, in order to write generic code, the same key set before must be
 * used here.
 *
 * The msg_len and data_len must be specified for modes which are not online
 * (e.g. CCM). Otherwise, they can be zero.
 *
 * @param[out] ctx			- the context.
 * @param[in] key			- the key
 * @param[in] key_len		- the key length in bytes.
 * @param[in] iv			- the initialization vector (IV).
 * @param[in] iv_len		- the IV length in bytes.
 * @param[in] msg_len		- the length in bytes of the message to be processed.
 * @param[in] data_len		- the length in bytes of additional data to be processed.
 */
errno_t ac_gcm_init(ac_gcm_ctx_t ctx, unsigned char *key, size_t key_len,
		unsigned char *iv, size_t iv_len, size_t msg_len, size_t data_len);

/**
 * Inputs additional data to be authenticated only.
 *
 * The data buffer must be aligned. It must have BC_BLOCK_LEN bytes, except for
 * the last call when it can have 0 < data_len <= BC_BLOCK_LEN.
 *
 * @param[in,out] ctx		- the context.
 * @param[in] data			- the additional data.
 * @param[in] data_len		- the length in bytes of the data.
 */
void ac_gcm_data(ac_gcm_ctx_t ctx, unsigned char *data, size_t data_len);

/**
 * Encrypts plaintext.
 *
 * The input buffer must be aligned. It must have BC_BLOCK_LEN bytes, except for
 * the last call when it can have 0 < input_len <= BC_BLOCK_LEN.
 *
 * @param[in,out] ctx		- the context.
 * @param[out] output		- the ciphertext generated.
 * @param[in] input			- hte plaintext to encrypt.
 * @param[in] input_len		- the length in bytes of the plaintext.
 */
void ac_gcm_enc(ac_gcm_ctx_t ctx, unsigned char *output, unsigned char *input, size_t input_len);

/**
 * Decrypts ciphertext.
 *
 * The input buffer must be aligned. It must have BC_BLOCK_LEN bytes, except for
 * the last call when it can have 0 < input_len <= BC_BLOCK_LEN.
 *
 * @param[in,out] ctx		- the context.
 * @param[out] output		- the plaintext generated.
 * @param[in] input			- hte ciphertext to decrypt.
 * @param[in] input_len		- the length in bytes of the ciphertext.
 */
void ac_gcm_dec(ac_gcm_ctx_t ctx, unsigned char *output, unsigned char *input, size_t input_len);

/**
 * Computes the authentication tag.
 *
 * This finishes the authenticated encryption process.
 *
 * @param[in] ctx		- the context.
 * @param[out] tag		- the buffer for the authentication tag.
 * @param[in] tag_len	- the length of the buffer.
 */
errno_t ac_gcm_tag(ac_gcm_ctx_t ctx, unsigned char *tag, size_t tag_len);

/**
 * Checks the authentication tag.
 *
 * This finishes the decryption-verification process.
 *
 * @param[in] ctx		- the context.
 * @param[in] tag		- the authentication tag received.
 * @param[in] tag_len	- the length of the authentication tag received.
 * @return 1 if the tag is valid, 0 otherwise.
 */
int ac_gcm_check(ac_gcm_ctx_t ctx, unsigned char *tag, size_t tag_len);

void ac_gcm_mul_low(dig_t *c, dig_t *a, dig_t *b);

void ac_gcm_tab_low(dig_t *t, unsigned char *h);

#endif /* AUTHENC_AC_H_ */
