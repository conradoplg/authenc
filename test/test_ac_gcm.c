#include "authenc_ac_gcm.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "authenc_errors.h"

static errno_t test_gcm(void) {
	errno_t err = AUTHENC_OK;
	unsigned char key[AC_GCM_KEY_LEN];
	unsigned char iv[AC_GCM_IV_LEN];
	authenc_align unsigned char msg[AC_GCM_BLOCK_LEN];
	authenc_align unsigned char cipher[AC_GCM_BLOCK_LEN];
	unsigned char tag[AC_GCM_TAG_LEN];
	ac_gcm_ctx_at ctx;

#if AC_GCM_KEY_LEN == 16

	puts("GCM passes test vector 13?");
	{
		unsigned char tag_ref[] = { 0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a };
		memset(key, 0, sizeof(key));
		memset(iv, 0, sizeof(iv));
		ac_gcm_key(ctx, key, sizeof(key));
		ac_gcm_init(ctx, key, sizeof(key), iv, sizeof(iv), 0, 0);
		ac_gcm_tag(ctx, tag, sizeof(tag));
		assert(memcmp(tag, tag_ref, sizeof(tag)) == 0);
	}

	puts("GCM passes test vector 14?");
	{
		authenc_align unsigned char cipher_ref[] = { 0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78 };
		unsigned char tag_ref[] = { 0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf };
		memset(key, 0, sizeof(key));
		memset(iv, 0, sizeof(iv));
		memset(msg, 0, sizeof(msg));
		ac_gcm_key(ctx, key, sizeof(key));
		ac_gcm_init(ctx, key, sizeof(key), iv, sizeof(iv), 0, 0);
		ac_gcm_enc(ctx, cipher, msg, sizeof(msg));
		ac_gcm_tag(ctx, tag, sizeof(tag));
		assert(memcmp(cipher, cipher_ref, sizeof(cipher)) == 0);
		assert(memcmp(tag, tag_ref, sizeof(tag)) == 0);
	}
#endif

	return err;
}

int main(void) {
	if (test_gcm() != AUTHENC_OK) {
		return 1;
	}
	puts("OK!");
	return 0;
}
