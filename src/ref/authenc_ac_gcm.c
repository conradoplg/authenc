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

#ifndef AC_GCM_REFLC
/** Table used to reflect the bits inside a byte. */
static const unsigned char byte_table[] = { 0x0, 0x80, 0x40, 0xc0, 0x20,
		0xa0, 0x60, 0xe0, 0x10, 0x90, 0x50, 0xd0, 0x30, 0xb0, 0x70,
		0xf0, 0x8, 0x88, 0x48, 0xc8, 0x28, 0xa8, 0x68, 0xe8, 0x18,
		0x98, 0x58, 0xd8, 0x38, 0xb8, 0x78, 0xf8, 0x4, 0x84, 0x44,
		0xc4, 0x24, 0xa4, 0x64, 0xe4, 0x14, 0x94, 0x54, 0xd4, 0x34,
		0xb4, 0x74, 0xf4, 0xc, 0x8c, 0x4c, 0xcc, 0x2c, 0xac, 0x6c,
		0xec, 0x1c, 0x9c, 0x5c, 0xdc, 0x3c, 0xbc, 0x7c, 0xfc, 0x2,
		0x82, 0x42, 0xc2, 0x22, 0xa2, 0x62, 0xe2, 0x12, 0x92, 0x52,
		0xd2, 0x32, 0xb2, 0x72, 0xf2, 0xa, 0x8a, 0x4a, 0xca, 0x2a,
		0xaa, 0x6a, 0xea, 0x1a, 0x9a, 0x5a, 0xda, 0x3a, 0xba, 0x7a,
		0xfa, 0x6, 0x86, 0x46, 0xc6, 0x26, 0xa6, 0x66, 0xe6, 0x16,
		0x96, 0x56, 0xd6, 0x36, 0xb6, 0x76, 0xf6, 0xe, 0x8e, 0x4e,
		0xce, 0x2e, 0xae, 0x6e, 0xee, 0x1e, 0x9e, 0x5e, 0xde, 0x3e,
		0xbe, 0x7e, 0xfe, 0x1, 0x81, 0x41, 0xc1, 0x21, 0xa1, 0x61,
		0xe1, 0x11, 0x91, 0x51, 0xd1, 0x31, 0xb1, 0x71, 0xf1, 0x9,
		0x89, 0x49, 0xc9, 0x29, 0xa9, 0x69, 0xe9, 0x19, 0x99, 0x59,
		0xd9, 0x39, 0xb9, 0x79, 0xf9, 0x5, 0x85, 0x45, 0xc5, 0x25,
		0xa5, 0x65, 0xe5, 0x15, 0x95, 0x55, 0xd5, 0x35, 0xb5, 0x75,
		0xf5, 0xd, 0x8d, 0x4d, 0xcd, 0x2d, 0xad, 0x6d, 0xed, 0x1d,
		0x9d, 0x5d, 0xdd, 0x3d, 0xbd, 0x7d, 0xfd, 0x3, 0x83, 0x43,
		0xc3, 0x23, 0xa3, 0x63, 0xe3, 0x13, 0x93, 0x53, 0xd3, 0x33,
		0xb3, 0x73, 0xf3, 0xb, 0x8b, 0x4b, 0xcb, 0x2b, 0xab, 0x6b,
		0xeb, 0x1b, 0x9b, 0x5b, 0xdb, 0x3b, 0xbb, 0x7b, 0xfb, 0x7,
		0x87, 0x47, 0xc7, 0x27, 0xa7, 0x67, 0xe7, 0x17, 0x97, 0x57,
		0xd7, 0x37, 0xb7, 0x77, 0xf7, 0xf, 0x8f, 0x4f, 0xcf, 0x2f,
		0xaf, 0x6f, 0xef, 0x1f, 0x9f, 0x5f, 0xdf, 0x3f, 0xbf, 0x7f,
		0xff };
#endif

/**
 * Convert byte stream to GCM representation.
 *
 * Since GCM treats the bits inside a byte in reverse order, we must convert it
 * to a suitable representation.
 *
 * @param[out] c			- the output block.
 * @param[in] a				- the input block.
 */
#if defined(AC_GCM_REFLC)
static void convert(unsigned char *c, unsigned char *a) {
	bc_t t;
	int i, j;
#ifdef BIGED
	dig_t *ad = (dig_t *) a;
	dig_t *td = (dig_t *) t;
	for (i = 0; i < AC_GCM_BLOCK_LEN / sizeof(dig_t); i += 1) {
		td[AC_GCM_BLOCK_LEN / sizeof(dig_t) - i - 1] = ad[i];
	}
#else
	for (i = 0; i < AC_GCM_BLOCK_LEN; i += sizeof(dig_t)) {
		for (j = 0; j < sizeof(dig_t); j++) {
			t[(AC_GCM_BLOCK_LEN - i - sizeof(dig_t)) + j] = a[i + (sizeof(dig_t) - j - 1)];
		}
	}
#endif
	memcpy(c, t, AC_GCM_BLOCK_LEN);
}
#else
static void convert(unsigned char *c, unsigned char *a) {
	int i;
#ifdef BIGED
	uint32_t *p = (uint32_t *) block;
	for (i = 0; i < AC_GCM_BLOCK_LEN / sizeof(uint32_t); i++) {
		p[i] = util_conv_little(p[i]);
	}
#endif
	for (i = 0; i < AC_GCM_BLOCK_LEN; i++) {
		c[i] = byte_table[a[i]];
	}
}
#endif

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

errno_t ac_gcm_key(ac_gcm_ctx_t ctx, unsigned char *key, size_t key_len) {
	authenc_align unsigned char h[AC_GCM_BLOCK_LEN];
	errno_t err = AUTHENC_OK;

	ctx->len_a = ctx->len_c = 0;

	memset(ctx->last_y, 0, AC_GCM_BLOCK_LEN);
	err = bc_aes_enc_key(ctx->bc_ctx, key, key_len);
	if (err != AUTHENC_OK) {
		return err;
	}

	//H = CIPH_K(0^128)
	bc_aes_enc(ctx->bc_ctx, h, ctx->last_y);
	convert(h, h);
	ac_gcm_tab_low(ctx->table, h);
	return AUTHENC_OK;
}

errno_t ac_gcm_init(ac_gcm_ctx_t ctx, unsigned char *key, size_t key_len,
		unsigned char *iv, size_t iv_len, size_t msg_len, size_t data_len) {
	if (key_len != AC_GCM_KEY_LEN || iv_len != AC_GCM_IV_LEN) {
		return AUTHENC_ERR_INVALID_PARAMETER;
	}
	(void) key;
	(void) key_len;
	(void) msg_len;
	(void) data_len;
	//J_0 = IV || 0^31 || 1
	memcpy(ctx->bc_ctx->iv, iv, AC_GCM_IV_LEN);
	memset(ctx->bc_ctx->iv + AC_GCM_IV_LEN, 0, AC_GCM_BLOCK_LEN - AC_GCM_IV_LEN);
	ctx->bc_ctx->iv[AC_GCM_BLOCK_LEN - 1] = 1;
	authenc_inc32(ctx->bc_ctx->iv, AC_GCM_BLOCK_LEN);
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

void ac_gcm_enc(ac_gcm_ctx_t ctx, unsigned char *output, unsigned char *input,
		size_t input_len) {
	authenc_align unsigned char t[AC_GCM_BLOCK_LEN];

	bc_aes_enc(ctx->bc_ctx, t, ctx->bc_ctx->iv);
	authenc_inc32(ctx->bc_ctx->iv, AC_GCM_BLOCK_LEN);
	if (input_len < AC_GCM_BLOCK_LEN) {
		authenc_xor(output, input, t, input_len);
		memset(t, 0, sizeof(t));
		memcpy(t, output, input_len);
		convert(t, t);
		authenc_xor(ctx->last_y, ctx->last_y, t, AC_GCM_BLOCK_LEN);
	} else {
		authenc_xor(output, input, t, AC_GCM_BLOCK_LEN);
		convert(t, output);
		authenc_xor(ctx->last_y, ctx->last_y, t, AC_GCM_BLOCK_LEN);
	}

	ac_gcm_mul_low((dig_t *) ctx->last_y, (dig_t *) ctx->last_y,
			(dig_t *) ctx->table);

	ctx->len_c += input_len;
}

void ac_gcm_dec(ac_gcm_ctx_t ctx, unsigned char *output, unsigned char *input,
		size_t input_len) {
	authenc_align unsigned char t[AC_GCM_BLOCK_LEN];

	bc_aes_enc(ctx->bc_ctx, t, ctx->bc_ctx->iv);
	authenc_inc32(ctx->bc_ctx->iv, AC_GCM_BLOCK_LEN);
	if (input_len < AC_GCM_BLOCK_LEN) {
		authenc_xor(output, input, t, input_len);
		memset(t, 0, sizeof(t));
		memcpy(t, input, input_len);
		convert(t, t);
		authenc_xor(ctx->last_y, ctx->last_y, t, AC_GCM_BLOCK_LEN);
	} else {
		authenc_xor(output, input, t, AC_GCM_BLOCK_LEN);
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
	memset(ctx->bc_ctx->iv + AC_GCM_IV_LEN, 0, AC_GCM_BLOCK_LEN - AC_GCM_IV_LEN);
	ctx->bc_ctx->iv[AC_GCM_BLOCK_LEN - 1] = 1;
	bc_aes_enc(ctx->bc_ctx, t, ctx->bc_ctx->iv);
	authenc_xor(t, t, ctx->last_y, AC_GCM_BLOCK_LEN);

	memcpy(tag, t, AC_GCM_TAG_LEN);
	return AUTHENC_OK;
}

errno_t ac_gcm_check(ac_gcm_ctx_t ctx, unsigned char *tag, size_t tag_len) {
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
