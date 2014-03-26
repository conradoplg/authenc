#include "authenc_ac_gcm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "authenc_errors.h"

static void rand_bytes(void *p, size_t len) {
	unsigned char *c = (unsigned char *) p;
	size_t i;

	for (i = 0; i < len; i++) {
		c[i] = rand();
	}
}

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

static errno_t test_ac(void) {
	errno_t err = AUTHENC_OK;
	unsigned char key[AC_GCM_KEY_LEN];
	unsigned char iv[AC_GCM_IV_LEN];
	authenc_align unsigned char msg[AC_GCM_BLOCK_LEN];
	authenc_align unsigned char cipher[sizeof(msg)];
	authenc_align unsigned char computed_msg[sizeof(msg)];
	unsigned char tag[AC_GCM_TAG_LEN];
	ac_gcm_ctx_at ctx;
	size_t j;

	rand_bytes(key, sizeof(key));
	rand_bytes(iv, sizeof(iv));
	rand_bytes(msg, sizeof(msg));

	rand_bytes(cipher, sizeof(cipher));
	ac_gcm_key(ctx, key, sizeof(key));
	ac_gcm_init(ctx, key, sizeof(key), iv, sizeof(iv), sizeof(msg), sizeof(msg));
	ac_gcm_enc(ctx, cipher, msg, sizeof(msg));
	ac_gcm_data(ctx, msg, sizeof(msg));
	ac_gcm_tag(ctx, tag, sizeof(tag));

	rand_bytes(computed_msg, sizeof(computed_msg));
	ac_gcm_key(ctx, key, sizeof(key));
	ac_gcm_init(ctx, key, sizeof(key), iv, sizeof(iv), sizeof(msg), sizeof(msg));
	ac_gcm_dec(ctx, computed_msg, cipher, sizeof(msg));
	ac_gcm_data(ctx, msg, sizeof(msg));
	assert(memcmp(msg, computed_msg, sizeof(msg)) == 0);
	assert(ac_gcm_check(ctx, tag, sizeof(tag)) == AUTHENC_OK);

	rand_bytes(computed_msg, sizeof(computed_msg));
	ac_gcm_key(ctx, key, sizeof(key));
	ac_gcm_init(ctx, key, sizeof(key), iv, sizeof(iv), sizeof(msg), sizeof(msg));
	ac_gcm_dec(ctx, computed_msg, cipher, sizeof(msg));
	ac_gcm_data(ctx, msg, sizeof(msg));
	rand_bytes(tag, sizeof(tag));
	assert(ac_gcm_check(ctx, tag, sizeof(tag)) != AUTHENC_OK);

	for (j = 1; j < sizeof(msg); j++) {
		printf("Testing message with size %zu\n", sizeof(msg) - j);
		rand_bytes(key, sizeof(key));
		rand_bytes(iv, sizeof(iv));
		rand_bytes(msg, sizeof(msg));

		rand_bytes(cipher, sizeof(cipher));
		ac_gcm_key(ctx, key, sizeof(key));
		ac_gcm_init(ctx, key, sizeof(key), iv, sizeof(iv), sizeof(msg)-j, sizeof(msg)-j);
		ac_gcm_enc(ctx, cipher, msg, sizeof(msg)-j);
		ac_gcm_data(ctx, msg, sizeof(msg)-j);
		ac_gcm_tag(ctx, tag, sizeof(tag));

		rand_bytes(computed_msg, sizeof(computed_msg));
		ac_gcm_key(ctx, key, sizeof(key));
		ac_gcm_init(ctx, key, sizeof(key), iv, sizeof(iv), sizeof(msg)-j, sizeof(msg)-j);
		ac_gcm_dec(ctx, computed_msg, cipher, sizeof(msg)-j);
		ac_gcm_data(ctx, msg, sizeof(msg)-j);
		assert(memcmp(msg, computed_msg, sizeof(msg)-j) == 0);
		assert(ac_gcm_check(ctx, tag, sizeof(tag)) == AUTHENC_OK);
	}

	return err;
}

int crypto_secretbox(unsigned char *c, const unsigned char *m,
		unsigned long long mlen, const unsigned char *n, const unsigned char *k);
int crypto_secretbox_open(unsigned char *m, const unsigned char *c,
		unsigned long long clen, const unsigned char *n, const unsigned char *k);

errno_t test_supercop(void) {
	errno_t err = AUTHENC_OK;
	unsigned char key[AC_GCM_KEY_LEN] = {0};
	unsigned char iv[AC_GCM_IV_LEN] = {0};
	authenc_align unsigned char msg[3 * AC_GCM_BLOCK_LEN + 1] = {0};
	authenc_align unsigned char cipher[3 * AC_GCM_BLOCK_LEN + 1] = {0};
	authenc_align unsigned char computed_msg[3 * AC_GCM_BLOCK_LEN + 1] = {0};
	int r;

	r = crypto_secretbox(cipher, msg, sizeof(msg), iv, key);
	assert(r == 0);
	r = crypto_secretbox_open(computed_msg, cipher, sizeof(cipher), iv, key);
	assert(r == 0);
	assert(memcmp(msg, computed_msg, sizeof(msg)) == 0);

	return err;
}

int main(void) {
	if (test_gcm() != AUTHENC_OK) {
		return 1;
	}
	if (test_ac() != AUTHENC_OK) {
		return 1;
	}
	if (test_supercop() != AUTHENC_OK) {
		return 1;
	}
	puts("OK!");
	return 0;
}
