#include "authenc_ac_gcm.h"

#include <stdlib.h>
#include <string.h>

#include "authenc_conf.h"
#include "authenc_util.h"
#include "authenc_errors.h"

/*============================================================================*/
/* Low-level function prototypes                                              */
/*============================================================================*/

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
errno_t ac_gcm_init_low(ac_gcm_ctx_t ctx, const unsigned char *key, size_t key_len,
		const unsigned char *iv, size_t iv_len, size_t msg_len, size_t data_len);

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
void ac_gcm_data_low(ac_gcm_ctx_t ctx, const unsigned char *data, size_t data_len);

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
void ac_gcm_enc_low(ac_gcm_ctx_t ctx, unsigned char *output, const unsigned char *input, size_t input_len);

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
void ac_gcm_dec_low(ac_gcm_ctx_t ctx, unsigned char *output, const unsigned char *input, size_t input_len);

/**
 * Computes the authentication tag.
 *
 * This finishes the authenticated encryption process.
 *
 * @param[in] ctx		- the context.
 * @param[out] tag		- the buffer for the authentication tag.
 * @param[in] tag_len	- the length of the buffer.
 */
errno_t ac_gcm_tag_low(ac_gcm_ctx_t ctx, unsigned char *tag, size_t tag_len);

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
int ac_gcm_check_low(ac_gcm_ctx_t ctx, const unsigned char *tag, size_t tag_len);

/**
 * Multiply two digit vectors in the GCM finite field.
 * @param[out] c	- the product.
 * @param[in] a		- the first operand.
 * @param[in] b		- the second operand.
 */
void ac_gcm_mul_low(dig_t *c, dig_t *a, dig_t *b);

/**
 * Build a precomputation table to help the GCM multiplication.
 *
 * @param[out] t	- the table.
 * @param[in] h		- the H value with AC_GCM_BLOCK_LEN bytes.
 */
void ac_gcm_tab_low(dig_t *t, unsigned char *h);

/**
 * Convert a byte vector to the internal representation.
 *
 * @param[out] c	- the converted vector with AC_GCM_BLOCK_LEN bytes.
 * @param[in] a		- the input with AC_GCM_BLOCK_LEN bytes.
 */
void ac_gcm_convert_low(unsigned char *c, const unsigned char *a);


/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Inputs a block into the GHASH function.
 *
 * @param[in,out] ctx		- the context.
 * @param[in] input			- the input block with AC_GCM_BLOCK_LEN bytes.
 */
static void ghash_input(ac_gcm_ctx_t ctx, const unsigned char *input) {
	authenc_align unsigned char t[AC_GCM_BLOCK_LEN];
	//xor (field addition)
	ac_gcm_convert_low(t, input);
	authenc_xor(ctx->last_y, ctx->last_y, t, AC_GCM_BLOCK_LEN);
	//binary field multiplication
	ac_gcm_mul_low((dig_t *) ctx->last_y, (dig_t *) ctx->last_y, (dig_t *) ctx->table);
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

errno_t ac_gcm_key(ac_gcm_ctx_t ctx, const unsigned char *key, size_t key_len) {
	authenc_align unsigned char h[AC_GCM_BLOCK_LEN];
	authenc_align unsigned char zero[AC_GCM_BLOCK_LEN] = { 0 };
	errno_t err = AUTHENC_OK;

	ctx->len_a = ctx->len_c = 0;

	memset(ctx->last_y, 0, AC_GCM_BLOCK_LEN);
	err = sc_aesctr_key(ctx->bc_ctx, key, key_len);
	if (err != AUTHENC_OK) {
		return err;
	}

	//H = CIPH_K(0^128)
	sc_aesctr_enc(ctx->bc_ctx, h, zero, sizeof(zero), ctx->last_y, AC_GCM_BLOCK_LEN);
	ac_gcm_convert_low(h, h);
	ac_gcm_tab_low(ctx->table, h);
	return AUTHENC_OK;
}

errno_t ac_gcm_init_low(ac_gcm_ctx_t ctx, const unsigned char *key, size_t key_len,
		const unsigned char *iv, size_t iv_len, size_t msg_len, size_t data_len) {
	if (iv_len != AC_GCM_IV_LEN) {
		return AUTHENC_ERR_INVALID_PARAMETER;
	}
	(void) key;
	(void) key_len;
	(void) msg_len;
	(void) data_len;
	//J_0 = IV || 0^31 || 1
	memcpy(ctx->ctr, iv, AC_GCM_IV_LEN);
	memset(ctx->ctr + AC_GCM_IV_LEN, 0, AC_GCM_BLOCK_LEN - AC_GCM_IV_LEN);
	ctx->ctr[AC_GCM_BLOCK_LEN - 1] = 1;
	authenc_inc32(ctx->ctr, 1, AC_GCM_BLOCK_LEN);
	return AUTHENC_OK;
}

void ac_gcm_data_low(ac_gcm_ctx_t ctx, const unsigned char *data, size_t data_len) {
	authenc_align unsigned char tmp[AC_GCM_BLOCK_LEN];
	const unsigned char *t = data;
	if (data_len < AC_GCM_BLOCK_LEN) {
		t = tmp;
		memcpy(tmp, data, data_len);
		memset(tmp + data_len, 0, AC_GCM_BLOCK_LEN - data_len);
	}
	ghash_input(ctx, t);
	ctx->len_a += data_len;
}

void ac_gcm_enc_low(ac_gcm_ctx_t ctx, unsigned char *output, const unsigned char *input,
		size_t input_len) {
	authenc_align unsigned char t[AC_GCM_BLOCK_LEN];
	size_t i, len;

	sc_aesctr_enc(ctx->bc_ctx, output, input, input_len, ctx->ctr, sizeof(ctx->ctr));
	authenc_inc32(ctx->ctr, input_len / AC_GCM_BLOCK_LEN, AC_GCM_BLOCK_LEN);
	len = (input_len / AC_GCM_BLOCK_LEN) * AC_GCM_BLOCK_LEN;
	for (i = 0; i < len; i += AC_GCM_BLOCK_LEN) {
		ghash_input(ctx, output + i);
	}
	len = input_len % AC_GCM_BLOCK_LEN;
	if (len) {
		memcpy(t, output + i, len);
		memset(t + len, 0, sizeof(t) - len);
		ghash_input(ctx, t);
	}

	ctx->len_c += input_len;
}

void ac_gcm_dec_low(ac_gcm_ctx_t ctx, unsigned char *output, const unsigned char *input,
		size_t input_len) {
	authenc_align unsigned char t[AC_GCM_BLOCK_LEN];
	size_t i, len;

	sc_aesctr_enc(ctx->bc_ctx, output, input, input_len, ctx->ctr, sizeof(ctx->ctr));
	authenc_inc32(ctx->ctr, input_len / AC_GCM_BLOCK_LEN, AC_GCM_BLOCK_LEN);
	len = (input_len / AC_GCM_BLOCK_LEN) * AC_GCM_BLOCK_LEN;
	for (i = 0; i < len; i += AC_GCM_BLOCK_LEN) {
		ghash_input(ctx, input + i);
	}
	len = input_len % AC_GCM_BLOCK_LEN;
	if (len) {
		memcpy(t, input + i, len);
		memset(t + len, 0, sizeof(t) - len);
		ghash_input(ctx, t);
	}

	ctx->len_c += input_len;
}

errno_t ac_gcm_tag_low(ac_gcm_ctx_t ctx, unsigned char *tag, size_t tag_len) {
	authenc_align unsigned char t[AC_GCM_BLOCK_LEN];

	if (tag_len != AC_GCM_TAG_LEN) {
		return AUTHENC_ERR_INVALID_PARAMETER;
	}

	//Build [len(A)]_64 || [len(C)]_64
	authenc_write64(t, 8 * ctx->len_a);
	authenc_write64(t + sizeof(uint64_t), 8 * ctx->len_c);
	ghash_input(ctx, t);

	//Compute S
	ac_gcm_convert_low(ctx->last_y, ctx->last_y);

	//Compute GCTR_K(J_0, S)
	memset(ctx->ctr + AC_GCM_IV_LEN, 0, AC_GCM_BLOCK_LEN - AC_GCM_IV_LEN);
	ctx->ctr[AC_GCM_BLOCK_LEN - 1] = 1;
	sc_aesctr_enc(ctx->bc_ctx, t, ctx->last_y, AC_GCM_BLOCK_LEN, ctx->ctr, AC_GCM_BLOCK_LEN);

	memcpy(tag, t, AC_GCM_TAG_LEN);
	return AUTHENC_OK;
}

errno_t ac_gcm_check_low(ac_gcm_ctx_t ctx, const unsigned char *tag, size_t tag_len) {
	unsigned char computed_tag[AC_GCM_TAG_LEN];

	if (tag_len != AC_GCM_TAG_LEN) {
		return AUTHENC_ERR_INVALID_PARAMETER;
	}

	ac_gcm_tag_low(ctx, computed_tag, sizeof(computed_tag));

	if (authenc_cmp_const(tag, computed_tag, AC_GCM_TAG_LEN) == 0) {
		return AUTHENC_OK;
	} else {
		return AUTHENC_ERR_AUTHENTICATION_FAILURE;
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

errno_t ac_gcm_enc(ac_gcm_ctx_t ctx, unsigned char *output, size_t *output_len, size_t output_capacity,
		const unsigned char *input, size_t input_len, const unsigned char *data,
		size_t data_len, const unsigned char *iv, size_t iv_len)
{
	errno_t err = AUTHENC_OK;

	if (!ctx || !output || !output_len || !iv || !iv_len) {
		return AUTHENC_ERR_INVALID_PARAMETER;
	}

	err = ac_gcm_init_low(ctx, NULL, 0, iv, iv_len, input_len, data_len);
	if (err != AUTHENC_OK) {
		return err;
	}

	if (input_len + AC_GCM_TAG_LEN < input_len) {
		return AUTHENC_ERR_INVALID_PARAMETER;
	}
	if (output_capacity < input_len + AC_GCM_TAG_LEN) {
		return AUTHENC_ERR_INVALID_PARAMETER;
	}
	*output_len = input_len + AC_GCM_TAG_LEN;

	if (data_len && data) {
		ac_gcm_data_low(ctx, data, data_len);
	}
	if (input && input_len) {
		ac_gcm_enc_low(ctx, output, input, input_len);
		output += input_len;
	}

	err = ac_gcm_tag_low(ctx, output, AC_GCM_TAG_LEN);
	if (err != AUTHENC_OK) {
		return err;
	}

	return err;
}

errno_t ac_gcm_dec(ac_gcm_ctx_t ctx, unsigned char *output, size_t *output_len, size_t output_capacity,
		const unsigned char *input, size_t input_len, const unsigned char *data,
		size_t data_len, const unsigned char *iv, size_t iv_len)
{
	errno_t err = AUTHENC_OK;

	if (!ctx || !output || !output_len) {
		return AUTHENC_ERR_INVALID_PARAMETER;
	}

	err = ac_gcm_init_low(ctx, NULL, 0, iv, iv_len, input_len, data_len);
	if (err != AUTHENC_OK) {
		return err;
	}

	if (input_len < AC_GCM_TAG_LEN) {
		return AUTHENC_ERR_INVALID_PARAMETER;
	}
	if (output_capacity < input_len - AC_GCM_TAG_LEN) {
		return AUTHENC_ERR_INVALID_PARAMETER;
	}
	*output_len = input_len - AC_GCM_TAG_LEN;

	if (data_len && data) {
		ac_gcm_data_low(ctx, data, data_len);
	}
	if (input && input_len) {
		ac_gcm_dec_low(ctx, output, input, *output_len);
		input += *output_len;
	}

	err = ac_gcm_check_low(ctx, input, AC_GCM_TAG_LEN);
	if (err != AUTHENC_OK) {
		authenc_memset(output, 0, *output_len);
		return err;
	}

	return err;
}
