#include <string.h>
#include <stdio.h>

#include "authenc_conf.h"
#include "authenc_errors.h"
#include "authenc_util.h"
#include "authenc_sc_aesctr.h"

#define crypto_stream_beforenm crypto_stream_aes128ctr_neon_beforenm
#define crypto_stream_xor_afternm_constants crypto_stream_aes128ctr_neon_xor_afternm_constants

extern int crypto_stream_beforenm(unsigned char *d, const unsigned char *k);

extern int crypto_stream_xor_afternm_constants(unsigned char *out,
		const unsigned char *in, unsigned long long inlen,
		const unsigned char *n, const unsigned char *d,
		const unsigned int *constants);

static const unsigned int constants[8] = { 0x00030201, 0x05040706, 0x02010003,
		0x07060504, 0x00000000, 0x00000000, 0x00000000, 0x00000001 };


errno_t sc_aesctr_key(sc_aesctr_ctx_t ctx, const unsigned char *key, size_t key_len) {
	unsigned char *ekey;
	if (key_len != SC_AES128CTR_KEY_LEN) {
		return AUTHENC_ERR_INVALID_PARAMETER;
	}
	ekey = ctx->aes_ctx->ekey + (15 & (-(intptr_t) ctx->aes_ctx->ekey));
	crypto_stream_beforenm(ekey, key);
	return AUTHENC_OK;
}

errno_t sc_aesctr_enc(sc_aesctr_ctx_t ctx, unsigned char *output,
		const unsigned char *input, size_t input_len,
		const unsigned char *nonce, size_t nonce_len)
{
	unsigned char *ekey;
	if (nonce_len != SC_AESCTR_IV_LEN) {
		return AUTHENC_ERR_INVALID_PARAMETER;
	}

	ekey = ctx->aes_ctx->ekey + (15 & (-(intptr_t) ctx->aes_ctx->ekey));
	crypto_stream_xor_afternm_constants(output, input, input_len, nonce, ekey, constants);

	return AUTHENC_OK;
}
