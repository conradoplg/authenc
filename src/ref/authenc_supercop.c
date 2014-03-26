#include <stdio.h>

//#include "crypto_secretbox.h"
#include "api.h"
#include "authenc_ac_gcm.h"
#include "authenc_errors.h"


int crypto_secretbox(unsigned char *c, const unsigned char *m,
		unsigned long long mlen, const unsigned char *n, const unsigned char *k)
{
	errno_t err = AUTHENC_OK;
	ac_gcm_ctx_at ctx;
	unsigned long long i = 0;

	if (mlen < crypto_secretbox_aes128gcm_ref_ZEROBYTES) {
		return -1;
	}
	err = ac_gcm_key(ctx, k, crypto_secretbox_aes128gcm_ref_KEYBYTES);
	if (err != AUTHENC_OK) {
		return -1;
	}
	err = ac_gcm_init(ctx, k, crypto_secretbox_aes128gcm_ref_KEYBYTES, n, crypto_secretbox_aes128gcm_ref_NONCEBYTES, 0, 0);
	if (err != AUTHENC_OK) {
		return -1;
	}
	for (i = crypto_secretbox_aes128gcm_ref_ZEROBYTES; i < (mlen - mlen % AC_GCM_BLOCK_LEN); i += AC_GCM_BLOCK_LEN) {
		ac_gcm_enc(ctx, c + i, m + i, AC_GCM_BLOCK_LEN);
	}
	if (i < mlen) {
		ac_gcm_enc(ctx, c + i, m + i, mlen - i);
	}
	err = ac_gcm_tag(ctx, c, crypto_secretbox_aes128gcm_ref_ZEROBYTES);
	if (err != AUTHENC_OK) {
		return -1;
	}
	return 0;
}

int crypto_secretbox_open(unsigned char *m, const unsigned char *c,
		unsigned long long clen, const unsigned char *n, const unsigned char *k)
{
	errno_t err = AUTHENC_OK;
	ac_gcm_ctx_at ctx;
	unsigned long long i;

	if (clen < crypto_secretbox_aes128gcm_ref_ZEROBYTES) {
		return -1;
	}
	err = ac_gcm_key(ctx, k, crypto_secretbox_aes128gcm_ref_KEYBYTES);
	if (err != AUTHENC_OK) {
		return -1;
	}
	err = ac_gcm_init(ctx, k, crypto_secretbox_aes128gcm_ref_KEYBYTES, n, crypto_secretbox_aes128gcm_ref_NONCEBYTES, 0, 0);
	if (err != AUTHENC_OK) {
		return -1;
	}
	for (i = crypto_secretbox_aes128gcm_ref_ZEROBYTES; i < (clen - clen % AC_GCM_BLOCK_LEN); i += AC_GCM_BLOCK_LEN) {
		ac_gcm_dec(ctx, m + i, c + i, AC_GCM_BLOCK_LEN);
	}
	if (i < clen) {
		ac_gcm_dec(ctx, m + i, c + i, clen - i);
	}
	err = ac_gcm_check(ctx, c, crypto_secretbox_aes128gcm_ref_ZEROBYTES);
	if (err != AUTHENC_OK) {
		return -1;
	}
	for (i = 0; i < crypto_secretbox_aes128gcm_ref_ZEROBYTES; i++) {
		m[i] = 0;
	}
	return 0;
}
