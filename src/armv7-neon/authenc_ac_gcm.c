#include "authenc_ac_gcm.h"

#include <stdlib.h>
#include <string.h>

#include "authenc_conf.h"
#include "authenc_util.h"
#include "authenc_errors.h"


/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

void ac_gcm_mul_low(dig_t *c, dig_t *a, dig_t *b);

void ac_gcm_tab_low(dig_t *t, unsigned char *h);

void ac_gcm_convert_low(unsigned char *c, const unsigned char *a);

/**
 * Convert byte stream to GCM representation.
 *
 * Since GCM treats the bits inside a byte in reverse order, we must convert it
 * to a suitable representation.
 *
 * @param[out] c			- the output block.
 * @param[in] a				- the input block.
 */
#define convert ac_gcm_convert_low

/**
 * Inputs a block into the GHASH function.
 *
 * @param[in,out] ctx		- the context.
 * @param[in] input			- the input block.
 */
static void ghash_input(ac_gcm_ctx_t ctx, unsigned char *input) {
	authenc_align unsigned char t[AC_GCM_BLOCK_LEN];
	//xor (field addition)
	convert(t, input);
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
	convert(h, h);
	ac_gcm_tab_low(ctx->table, h);
	return AUTHENC_OK;
}

errno_t ac_gcm_init(ac_gcm_ctx_t ctx, const unsigned char *key, size_t key_len,
		const unsigned char *iv, size_t iv_len, size_t msg_len, size_t data_len) {
	if (key_len != AC_GCM_KEY_LEN || iv_len != AC_GCM_IV_LEN) {
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
	authenc_inc32(ctx->ctr, AC_GCM_BLOCK_LEN);
	return AUTHENC_OK;
}

void ac_gcm_data(ac_gcm_ctx_t ctx, unsigned char *data, size_t data_len) {
	authenc_align unsigned char tmp[AC_GCM_BLOCK_LEN];
	unsigned char *t = data;
	if (data_len < AC_GCM_BLOCK_LEN) {
		t = tmp;
		memcpy(tmp, data, data_len);
		memset(tmp + data_len, 0, AC_GCM_BLOCK_LEN - data_len);
	}
	ghash_input(ctx, t);
	ctx->len_a += data_len;
}

void ac_gcm_enc(ac_gcm_ctx_t ctx, unsigned char *output, const unsigned char *input,
		size_t input_len) {
	authenc_align unsigned char t[AC_GCM_BLOCK_LEN];

	if (input_len < AC_GCM_BLOCK_LEN) {
		memset(t, 0, sizeof(t));
		memcpy(t, input, input_len);
		sc_aesctr_enc(ctx->bc_ctx, t, t, AC_GCM_BLOCK_LEN, ctx->ctr, AC_GCM_BLOCK_LEN);
		authenc_inc32(ctx->ctr, AC_GCM_BLOCK_LEN);
		memcpy(output, t, input_len);
		convert(t, t);
		authenc_xor(ctx->last_y, ctx->last_y, t, AC_GCM_BLOCK_LEN);
	} else {
		sc_aesctr_enc(ctx->bc_ctx, output, input, AC_GCM_BLOCK_LEN, ctx->ctr, AC_GCM_BLOCK_LEN);
		authenc_inc32(ctx->ctr, AC_GCM_BLOCK_LEN);
		convert(t, output);
		authenc_xor(ctx->last_y, ctx->last_y, t, AC_GCM_BLOCK_LEN);
	}

	ac_gcm_mul_low((dig_t *) ctx->last_y, (dig_t *) ctx->last_y,
			(dig_t *) ctx->table);

	ctx->len_c += input_len;
}

void ac_gcm_dec(ac_gcm_ctx_t ctx, unsigned char *output, const unsigned char *input,
		size_t input_len) {
	authenc_align unsigned char t[AC_GCM_BLOCK_LEN];

	if (input_len < AC_GCM_BLOCK_LEN) {
		memset(t, 0, sizeof(t));
		memcpy(t, input, input_len);
		sc_aesctr_enc(ctx->bc_ctx, t, t, AC_GCM_BLOCK_LEN, ctx->ctr, AC_GCM_BLOCK_LEN);
		authenc_inc32(ctx->ctr, AC_GCM_BLOCK_LEN);
		memcpy(output, t, input_len);
		memset(t, 0, sizeof(t));
		memcpy(t, input, input_len);
		convert(t, t);
		authenc_xor(ctx->last_y, ctx->last_y, t, AC_GCM_BLOCK_LEN);
	} else {
		sc_aesctr_enc(ctx->bc_ctx, output, input, AC_GCM_BLOCK_LEN, ctx->ctr, AC_GCM_BLOCK_LEN);
		authenc_inc32(ctx->ctr, AC_GCM_BLOCK_LEN);
		convert(t, input);
		authenc_xor(ctx->last_y, ctx->last_y, t, AC_GCM_BLOCK_LEN);
	}
	ac_gcm_mul_low((dig_t *) ctx->last_y, (dig_t *) ctx->last_y,
			(dig_t *) ctx->table);
	ctx->len_c += input_len;
}

errno_t ac_gcm_tag(ac_gcm_ctx_t ctx, unsigned char *tag, size_t tag_len) {
	authenc_align unsigned char t[AC_GCM_BLOCK_LEN];

	if (tag_len != AC_GCM_TAG_LEN) {
		return AUTHENC_ERR_INVALID_PARAMETER;
	}

	//Build [len(A)]_64 || [len(C)]_64
	authenc_write64(t, 8 * ctx->len_a);
	authenc_write64(t + sizeof(uint64_t), 8 * ctx->len_c);
	ghash_input(ctx, t);

	//Compute S
	convert(ctx->last_y, ctx->last_y);

	//Compute GCTR_K(J_0, S)
	memset(ctx->ctr + AC_GCM_IV_LEN, 0, AC_GCM_BLOCK_LEN - AC_GCM_IV_LEN);
	ctx->ctr[AC_GCM_BLOCK_LEN - 1] = 1;
	sc_aesctr_enc(ctx->bc_ctx, t, ctx->last_y, AC_GCM_BLOCK_LEN, ctx->ctr, AC_GCM_BLOCK_LEN);

	memcpy(tag, t, AC_GCM_TAG_LEN);
	return AUTHENC_OK;
}

errno_t ac_gcm_check(ac_gcm_ctx_t ctx, const unsigned char *tag, size_t tag_len) {
	unsigned char computed_tag[AC_GCM_TAG_LEN];

	if (tag_len != AC_GCM_TAG_LEN) {
		return AUTHENC_ERR_INVALID_PARAMETER;
	}

	ac_gcm_tag(ctx, computed_tag, sizeof(computed_tag));

	if (authenc_cmp_const(tag, computed_tag, AC_GCM_TAG_LEN) == 0) {
		return AUTHENC_OK;
	} else {
		return AUTHENC_ERR_AUTHENTICATION_FAILURE;
	}
}
