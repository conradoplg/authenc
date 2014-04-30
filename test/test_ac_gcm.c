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
	unsigned char key[SC_AES128CTR_KEY_LEN];
	unsigned char iv[AC_GCM_IV_LEN];
	authenc_align unsigned char msg[AC_GCM_BLOCK_LEN];
	authenc_align unsigned char cipher[AC_GCM_BLOCK_LEN + AC_GCM_TAG_LEN];
	unsigned char tag[AC_GCM_TAG_LEN];
	ac_gcm_ctx_at ctx;
	size_t len;

	puts("GCM passes test vector 13?");
	{
		unsigned char tag_ref[] = { 0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a };
		memset(key, 0, sizeof(key));
		memset(iv, 0, sizeof(iv));
		ac_gcm_key(ctx, key, sizeof(key));
		ac_gcm_enc(ctx, tag, &len, sizeof(tag), NULL, 0, NULL, 0, iv, sizeof(iv));
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
		ac_gcm_enc(ctx, cipher, &len, sizeof(cipher), msg, sizeof(msg), NULL, 0, iv, sizeof(iv));
		assert(memcmp(cipher, cipher_ref, AC_GCM_BLOCK_LEN) == 0);
		assert(memcmp(cipher + AC_GCM_BLOCK_LEN, tag_ref, AC_GCM_TAG_LEN) == 0);
	}

	return err;
}

static errno_t test_ac(void) {
	errno_t err = AUTHENC_OK;
	unsigned char key[SC_AES128CTR_KEY_LEN];
	unsigned char iv[AC_GCM_IV_LEN];
	authenc_align unsigned char msg[AC_GCM_BLOCK_LEN * 16];
	authenc_align unsigned char cipher[sizeof(msg) + AC_GCM_TAG_LEN];
	authenc_align unsigned char computed_msg[sizeof(msg)];
	ac_gcm_ctx_at ctx;
	size_t msg_len, dec_msg_len, cipher_len, j;

	rand_bytes(key, sizeof(key));
	rand_bytes(iv, sizeof(iv));
	rand_bytes(msg, sizeof(msg));

	puts("Randomized tests, aligned");
	for (msg_len = 0; msg_len < sizeof(msg); msg_len++) {
		//Aligned
		rand_bytes(cipher, sizeof(cipher));
		err = ac_gcm_key(ctx, key, sizeof(key));
		assert(err == AUTHENC_OK);
		err = ac_gcm_enc(ctx, cipher, &cipher_len, sizeof(cipher), msg, msg_len, msg, msg_len, iv, sizeof(iv));
		assert(err == AUTHENC_OK);

		rand_bytes(computed_msg, sizeof(computed_msg));
		err = ac_gcm_key(ctx, key, sizeof(key));
		assert(err == AUTHENC_OK);
		err = ac_gcm_dec(ctx, computed_msg, &dec_msg_len, sizeof(computed_msg), cipher, cipher_len, msg, msg_len, iv, sizeof(iv));
		assert(err == AUTHENC_OK);
		assert(dec_msg_len == msg_len && memcmp(msg, computed_msg, msg_len) == 0);
	}

#if 0
	puts("Randomized tests, misaligned");
	for (msg_len = 0; msg_len < sizeof(msg); msg_len++) {
		//Misaligned
		size_t offset = sizeof(msg) - msg_len - 1;
		rand_bytes(cipher, sizeof(cipher));
		err = ac_gcm_key(ctx, key, sizeof(key));
		assert(err == AUTHENC_OK);
		err = ac_gcm_enc(ctx, cipher + offset, &cipher_len, sizeof(cipher), msg + offset, msg_len, msg + offset, msg_len, iv, sizeof(iv));
		assert(err == AUTHENC_OK);

		rand_bytes(computed_msg, sizeof(computed_msg));
		err = ac_gcm_key(ctx, key, sizeof(key));
		assert(err == AUTHENC_OK);
		err = ac_gcm_dec(ctx, computed_msg + offset, &dec_msg_len, sizeof(computed_msg), cipher + offset, cipher_len, msg + offset, msg_len, iv, sizeof(iv));
		assert(err == AUTHENC_OK);
		assert(dec_msg_len == msg_len && memcmp(msg + offset, computed_msg + offset, msg_len) == 0);
	}
#endif

	puts("Corrupted ciphertext tests");
	rand_bytes(computed_msg, sizeof(computed_msg));
	err = ac_gcm_key(ctx, key, sizeof(key));
	assert(err == AUTHENC_OK);
	for (j = 0; j < (cipher_len * 8); j++) {
		cipher[j/8] ^= (1 << (cipher_len % 8));
		err = ac_gcm_dec(ctx, computed_msg, &dec_msg_len, sizeof(computed_msg), cipher, cipher_len, msg, msg_len, iv, sizeof(iv));
		assert(err != AUTHENC_OK);
		cipher[j/8] ^= (1 << (cipher_len % 8));
	}

	return err;
}

int crypto_secretbox(unsigned char *c, const unsigned char *m,
		unsigned long long mlen, const unsigned char *n, const unsigned char *k);
int crypto_secretbox_open(unsigned char *m, const unsigned char *c,
		unsigned long long clen, const unsigned char *n, const unsigned char *k);

errno_t test_supercop(void) {
	errno_t err = AUTHENC_OK;
	unsigned char key[SC_AES128CTR_KEY_LEN] = {0};
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
