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
	authenc_align unsigned char cipher[2 * AC_GCM_BLOCK_LEN + AC_GCM_TAG_LEN];
	unsigned char tag[AC_GCM_TAG_LEN];
	ac_gcm_ctx_at ctx;
	size_t len;

	puts("GCM passes test vector 13?");
	{
		unsigned char tag_ref[] = { 0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a };
		memset(key, 0, sizeof(key));
		memset(iv, 0, sizeof(iv));
		err = ac_gcm_key(ctx, key, sizeof(key));
		assert(err == AUTHENC_OK);
		err = ac_gcm_enc(ctx, tag, &len, sizeof(tag), NULL, 0, NULL, 0, iv, sizeof(iv));
		assert(err == AUTHENC_OK);
		assert(memcmp(tag, tag_ref, sizeof(tag)) == 0);
	}

	puts("GCM passes test vector 14?");
	{
		authenc_align unsigned char cipher_ref[] = { 0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78 };
		unsigned char tag_ref[] = { 0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf };
		memset(key, 0, sizeof(key));
		memset(iv, 0, sizeof(iv));
		memset(msg, 0, sizeof(msg));
		err = ac_gcm_key(ctx, key, sizeof(key));
		assert(err == AUTHENC_OK);
		err = ac_gcm_enc(ctx, cipher, &len, sizeof(cipher), msg, sizeof(msg), NULL, 0, iv, sizeof(iv));
		assert(err == AUTHENC_OK);
		assert(len == sizeof(cipher_ref) + sizeof(tag_ref));
		assert(memcmp(cipher, cipher_ref, sizeof(cipher_ref)) == 0);
		assert(memcmp(cipher + sizeof(cipher_ref), tag_ref, sizeof(tag_ref)) == 0);
	}

	puts("GCM passes test vector A?");
	{
		const unsigned char key[] = { 0x29, 0x8e, 0xfa, 0x1c, 0xcf, 0x29, 0xcf, 0x62, 0xae, 0x68, 0x24, 0xbf, 0xc1, 0x95, 0x57, 0xfc };
		const unsigned char iv[] = { 0x6f, 0x58, 0xa9, 0x3f, 0xe1, 0xd2, 0x07, 0xfa, 0xe4, 0xed, 0x2f, 0x6d };
		const unsigned char msg[] = { 0xcc, 0x38, 0xbc, 0xcd, 0x6b, 0xc5, 0x36, 0xad, 0x91, 0x9b, 0x13, 0x95,
				  0xf5, 0xd6, 0x38, 0x01, 0xf9, 0x9f, 0x80, 0x68, 0xd6, 0x5c, 0xa5, 0xac,
				  0x63, 0x87, 0x2d, 0xaf, 0x16, 0xb9, 0x39, 0x01 };
		const unsigned char data[] = { 0x02, 0x1f, 0xaf, 0xd2, 0x38, 0x46, 0x39, 0x73, 0xff, 0xe8, 0x02, 0x56,
				  0xe5, 0xb1, 0xc6, 0xb1 };
		const unsigned char cipher_ref[] = { 0xdf, 0xce, 0x4e, 0x9c, 0xd2, 0x91, 0x10, 0x3d, 0x7f, 0xe4, 0xe6, 0x33,
				  0x51, 0xd9, 0xe7, 0x9d, 0x3d, 0xfd, 0x39, 0x1e, 0x32, 0x67, 0x10, 0x46,
				  0x58, 0x21, 0x2d, 0xa9, 0x65, 0x21, 0xb7, 0xdb };
		const unsigned char tag_ref[] = { 0x54, 0x24, 0x65, 0xef, 0x59, 0x93, 0x16, 0xf7, 0x3a, 0x7a, 0x56, 0x05,
				  0x09, 0xa2, 0xd9, 0xf2 };
		err = ac_gcm_key(ctx, key, sizeof(key));
		assert(err == AUTHENC_OK);
		err = ac_gcm_enc(ctx, cipher, &len, sizeof(cipher), msg, sizeof(msg), data, sizeof(data), iv, sizeof(iv));
		assert(err == AUTHENC_OK);
		assert(len == sizeof(cipher_ref) + sizeof(tag_ref));
		assert(memcmp(cipher, cipher_ref, sizeof(cipher_ref)) == 0);
		assert(memcmp(cipher + sizeof(cipher_ref), tag_ref, sizeof(tag_ref)) == 0);
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

#if 1
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
        err = AUTHENC_OK;
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

int test_ac_gcm(void) {
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

int main(void) {
    return test_ac_gcm();
}
