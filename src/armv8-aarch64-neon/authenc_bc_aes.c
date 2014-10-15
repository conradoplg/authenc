#include "authenc_bc_aes.h"

#include <string.h>

#include "authenc_util.h"
#include "authenc_errors.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

uint32_t bc_aes_4sbox(uint32_t x);

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

errno_t bc_aes_enc_key(bc_aes_ctx_t ctx, const unsigned char *key, size_t len) {
	unsigned char rcon = 1;
	unsigned char t[4];
	size_t a, j;

	switch (len) {
	case 16:
		break;
	default:
		return AUTHENC_ERR_INVALID_PARAMETER;
	}

	//KeyExpansion
	memcpy(ctx->ekey, key, BC_AES128_KEY_LEN);
	for (a = 16; a < 11 * 16; ) {
		uint32_t y = bc_aes_4sbox(ctx->ekey[a - 3] | (ctx->ekey[a - 2] << 8) | (ctx->ekey[a - 1] << 16) | (ctx->ekey[a - 4] << 24));
		t[0] = (y & 0xFF) ^ rcon;
		t[1] = (y >> 8) & 0xFF;
		t[2] = (y >> 16) & 0xFF;
		t[3] = (y >> 24) & 0xFF;
		rcon = (rcon << 1) ^ ((rcon >> 7) * 0x11b);
		for (j = 0; j < 4; j++) {
			t[0] ^= ctx->ekey[a - 16];
			t[1] ^= ctx->ekey[a - 15];
			t[2] ^= ctx->ekey[a - 14];
			t[3] ^= ctx->ekey[a - 13];
			memcpy(ctx->ekey + a, t, 4);
			a += 4;
		}
	}
	return AUTHENC_OK;
}

errno_t bc_aes_dec_key(bc_aes_ctx_t ctx, const unsigned char *key, size_t len) {
	return bc_aes_enc_key(ctx, key, len);
}
