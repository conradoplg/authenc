#include "authenc_sc_aesctr.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "authenc_errors.h"

void dump(const void *p, int len) { const unsigned char *a = p; int i; for (i = 0; i < len; i++) { printf("%02X", a[i]); } puts(""); }
int crypto_stream_xor(
        unsigned char *out,
        const unsigned char *in,
        unsigned long long inlen,
        const unsigned char *n,
        const unsigned char *k
        );
static errno_t test_aes128ctr(void) {
	errno_t err = AUTHENC_OK;
	unsigned char keys[][BC_AES128_KEY_LEN] = {
			{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	};
	authenc_align unsigned char plaintexts[][BC_AES_BLOCK_LEN] = {
			{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	};
	authenc_align unsigned char ciphertexts[][BC_AES_BLOCK_LEN] = {
			{0x3A, 0xD7, 0x8E, 0x72, 0x6C, 0x1E, 0xC0, 0x2B, 0x7E, 0xBF, 0xE9, 0x2B, 0x23, 0xD9, 0xEC, 0x34},
			{0x0E, 0xDD, 0x33, 0xD3, 0xC6, 0x21, 0xE5, 0x46, 0x45, 0x5B, 0xD8, 0xBA, 0x14, 0x18, 0xBE, 0xC8},
	};
	authenc_align unsigned char t[BC_AES_BLOCK_LEN];
	authenc_align unsigned char zero[BC_AES_BLOCK_LEN] = {0};
	sc_aesctr_ctx_at ctx;
	size_t k;

	for (k = 0; k < (sizeof(keys) / sizeof(keys[0])); k++) {
		memset(t, 0, sizeof(t));
		sc_aesctr_key(ctx, keys[k], sizeof(keys[k]));
		sc_aesctr_enc(ctx, t, zero, sizeof(zero), plaintexts[k], sizeof(plaintexts[k]));
		assert(memcmp(t, ciphertexts[k], sizeof(t)) == 0);

		memset(t, 0, sizeof(t));
		sc_aesctr_key(ctx, keys[k], sizeof(keys[k]));
		sc_aesctr_enc(ctx, t, ciphertexts[k], sizeof(ciphertexts[k]), plaintexts[k], sizeof(plaintexts[k]));
		assert(memcmp(t, zero, sizeof(t)) == 0);
	}
	return err;
}

int main(void) {
	if (test_aes128ctr() != AUTHENC_OK) {
		return 1;
	}
	puts("OK!");
	return 0;
}
