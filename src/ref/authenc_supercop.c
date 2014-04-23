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
	size_t clen;

	if (mlen < crypto_secretbox_aes128gcm_ref_ZEROBYTES) {
		return -1;
	}
	err = ac_gcm_key(ctx, k, crypto_secretbox_aes128gcm_ref_KEYBYTES);
	if (err != AUTHENC_OK) {
		return -1;
	}
	err = ac_gcm_enc(ctx, c, &clen, mlen,
			m + crypto_secretbox_aes128gcm_ref_ZEROBYTES, mlen - crypto_secretbox_aes128gcm_ref_ZEROBYTES,
			NULL, 0, n, crypto_secretbox_aes128gcm_ref_NONCEBYTES);
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
	size_t mlen;

	if (clen < crypto_secretbox_aes128gcm_ref_ZEROBYTES) {
		return -1;
	}
	err = ac_gcm_key(ctx, k, crypto_secretbox_aes128gcm_ref_KEYBYTES);
	if (err != AUTHENC_OK) {
		return -1;
	}
	err = ac_gcm_dec(ctx, m + crypto_secretbox_aes128gcm_ref_ZEROBYTES, &mlen, clen - crypto_secretbox_aes128gcm_ref_ZEROBYTES,
			c, clen, NULL, 0, n, crypto_secretbox_aes128gcm_ref_NONCEBYTES);
	if (err != AUTHENC_OK) {
		return -1;
	}
	for (i = 0; i < crypto_secretbox_aes128gcm_ref_ZEROBYTES; i++) {
		m[i] = 0;
	}
	return 0;
}
