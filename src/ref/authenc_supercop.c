#include <stdio.h>

//#include "crypto_aead.h"
#include "api.h"
#include "authenc_ac_gcm.h"
#include "authenc_errors.h"

int crypto_aead_encrypt(
		unsigned char *c,unsigned long long *clen,
		const unsigned char *m,unsigned long long mlen,
		const unsigned char *ad,unsigned long long adlen,
		const unsigned char *nsec,
		const unsigned char *npub,
		const unsigned char *k
)
{
	errno_t err = AUTHENC_OK;
	ac_gcm_ctx_at ctx;
	//TODO: check overflow
	size_t clen_aux = *clen;
	(void) nsec;

	err = ac_gcm_key(ctx, k, CRYPTO_KEYBYTES);
	if (err != AUTHENC_OK) {
		return -1;
	}
	err = ac_gcm_enc(ctx, c, &clen_aux, clen_aux, m, mlen, ad, adlen, npub, CRYPTO_NPUBBYTES);
	if (err != AUTHENC_OK) {
		return -1;
	}

	return 0;
}

int crypto_aead_decrypt(
		unsigned char *m,unsigned long long *mlen,
		unsigned char *nsec,
		const unsigned char *c,unsigned long long clen,
		const unsigned char *ad,unsigned long long adlen,
		const unsigned char *npub,
		const unsigned char *k
)
{
	errno_t err = AUTHENC_OK;
	ac_gcm_ctx_at ctx;
	//TODO: check overflow
	size_t mlen_aux = *mlen;
	(void) nsec;

	err = ac_gcm_key(ctx, k, CRYPTO_KEYBYTES);
	if (err != AUTHENC_OK) {
		return -1;
	}
	err = ac_gcm_dec(ctx, m, &mlen_aux, mlen_aux, c, clen, ad, adlen, npub, CRYPTO_NPUBBYTES);
	if (err != AUTHENC_OK) {
		return -1;
	}
	return 0;
}
