#include <string.h>

#include "authenc_conf.h"
#include "authenc_errors.h"
#include "authenc_util.h"
#include "authenc_sc_aesctr.h"

errno_t sc_aesctr_key(sc_aesctr_ctx_t ctx, unsigned char *key, size_t key_len) {
	return bc_aes_enc_key(ctx->aes_ctx, key, key_len);
}

errno_t sc_aesctr_enc(sc_aesctr_ctx_t ctx, unsigned char *output,
		const unsigned char *input, size_t input_len,
		const unsigned char *nonce, size_t nonce_len)
{
	authenc_align unsigned char t[SC_AESCTR_BLOCK_LEN];
	authenc_align unsigned char ctr[SC_AESCTR_BLOCK_LEN];

	if (nonce_len != SC_AESCTR_IV_LEN) {
		return AUTHENC_ERR_INVALID_PARAMETER;
	}

	memcpy(ctr, nonce, sizeof(ctr));

	while (input_len) {
		bc_aes_enc(ctx->aes_ctx, t, ctr);
		authenc_inc32(ctr, sizeof(ctr));
		if (input_len < SC_AESCTR_BLOCK_LEN) {
			authenc_xor(output, input, t, input_len);
			input_len = 0;
		} else {
			authenc_xor(output, input, t, SC_AESCTR_BLOCK_LEN);
			input_len -= SC_AESCTR_BLOCK_LEN;
			output += SC_AESCTR_BLOCK_LEN;
			input += SC_AESCTR_BLOCK_LEN;
		}
	}
	return AUTHENC_OK;
}
