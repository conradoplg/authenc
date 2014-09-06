#include <stdio.h>

#ifdef SUPERCOP
#include "crypto_aead.h"
#endif
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
	size_t clen_aux;
	(void) nsec;

	err = ac_gcm_key(ctx, k, CRYPTO_KEYBYTES);
	if (err != AUTHENC_OK) {
		return -1;
	}
	*clen = mlen + CRYPTO_ABYTES;
	err = ac_gcm_enc(ctx, c, &clen_aux, mlen + CRYPTO_ABYTES, m, mlen, ad, adlen, npub, CRYPTO_NPUBBYTES);
	if (err != AUTHENC_OK) {
		return -1;
	}
	*clen = clen_aux;

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
	size_t mlen_aux;
	(void) nsec;

	err = ac_gcm_key(ctx, k, CRYPTO_KEYBYTES);
	if (err != AUTHENC_OK) {
		return -1;
	}
	*mlen = clen - CRYPTO_ABYTES;
	err = ac_gcm_dec(ctx, m, &mlen_aux, clen - CRYPTO_ABYTES, c, clen, ad, adlen, npub, CRYPTO_NPUBBYTES);
	if (err != AUTHENC_OK) {
		return -1;
	}
	*mlen = mlen_aux;
	return 0;
}
