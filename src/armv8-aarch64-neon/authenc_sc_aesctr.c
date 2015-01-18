#include <string.h>

#include "authenc_conf.h"
#include "authenc_errors.h"
#include "authenc_util.h"
#include "authenc_sc_aesctr.h"


extern void sc_aesctr_enc_low(unsigned char *output, const unsigned char *input,
                              size_t input_len, const unsigned char *nonce, const unsigned char *ekey);

errno_t sc_aesctr_key(sc_aesctr_ctx_t ctx, const unsigned char *key, size_t key_len) {
	return bc_aes_enc_key(ctx->aes_ctx, key, key_len);
}

errno_t sc_aesctr_enc(sc_aesctr_ctx_t ctx, unsigned char *output,
		const unsigned char *input, size_t input_len,
		const unsigned char *nonce, size_t nonce_len)
{
    size_t leftover_len;
    
	if (nonce_len != SC_AESCTR_IV_LEN) {
		return AUTHENC_ERR_INVALID_PARAMETER;
	}
    
    leftover_len = input_len % 32;
	sc_aesctr_enc_low(output, input, input_len - leftover_len, nonce, ctx->aes_ctx->ekey);
    if (leftover_len > 0) {
        unsigned char full_input[32], full_output[32], new_nonce[16];
        memcpy(new_nonce, nonce, sizeof(new_nonce));
        authenc_inc32(new_nonce, input_len / 32, sizeof(new_nonce));
        memcpy(full_input, input + input_len - leftover_len, leftover_len);
        sc_aesctr_enc_low(full_output, full_input, 32, nonce, ctx->aes_ctx->ekey);
        memcpy(output + input_len - leftover_len, full_output, leftover_len);
    }
	return AUTHENC_OK;
}
