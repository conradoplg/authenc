#include <stdio.h>
#include <assert.h>

#include "authenc_errors.h"
#include "authenc_ac_gcm.h"
#include "authenc_bench.h"

#define BENCH 128

#define MAX_SIZE 100000
static const unsigned int SIZES[] = {MAX_SIZE};

static void dummy(void)
{
    volatile int i = 0;
    for (i = 0; i < 100; i++)
        ;
}

static void dump(const void *p, size_t len) { const unsigned char *a = p; size_t i; for (i = 0; i < len; i++) { printf("%02X", a[i]); } puts(""); }

static void bench_authenticated_encryption(void) {
	unsigned char key[SC_AES128CTR_KEY_LEN] = { 0 };
	unsigned char iv[AC_GCM_IV_LEN] = { 0 };
	authenc_align unsigned char msg[MAX_SIZE] = { 0 };
	authenc_align unsigned char cipher[MAX_SIZE + AC_GCM_TAG_LEN];
	ac_gcm_ctx_at ctx;
	size_t k, msg_len, cipher_len;
    errno_t err;

	for (k = 0; k < sizeof(SIZES) / sizeof(int); k++) {
#undef BENCH
#define BENCH 1280
		BENCH_BEGIN("authenticated enc key setup") {
			BENCH_ADD(err = ac_gcm_key(ctx, key, sizeof(key)));
		}
		BENCH_END;
#undef BENCH
#define BENCH 128
        assert(err == AUTHENC_OK);
		BENCH_BEGIN("authenticated encryption") {
			BENCH_ADD(err = ac_gcm_enc(ctx, cipher, &cipher_len, sizeof(cipher), msg, SIZES[k], NULL, 0, iv, sizeof(iv)));
		}
		BENCH_END;
        
		err = ac_gcm_key(ctx, key, sizeof(key));
        assert(err == AUTHENC_OK);
		BENCH_BEGIN("decryption-verification") {
			BENCH_ADD(err = ac_gcm_dec(ctx, msg, &msg_len, sizeof(msg), cipher, cipher_len, NULL, 0, iv, sizeof(iv)));
		}
		BENCH_END;
        assert(err == AUTHENC_OK);
	}
}

static void bench_authentication(void) {
	unsigned char key[SC_AES128CTR_KEY_LEN];
	unsigned char iv[AC_GCM_IV_LEN];
	authenc_align unsigned char msg[SIZES[0]];
	authenc_align unsigned char cipher[AC_GCM_TAG_LEN];
	ac_gcm_ctx_at ctx;
	size_t k, msg_len, cipher_len;

	for (k = 0; k < sizeof(SIZES) / sizeof(int); k++) {
		ac_gcm_key(ctx, key, sizeof(key));
		BENCH_BEGIN("authentication") {
			BENCH_ADD(ac_gcm_enc(ctx, cipher, &cipher_len, sizeof(cipher), NULL, 0, msg, SIZES[k], iv, sizeof(iv)));
		}
		BENCH_END;

		ac_gcm_key(ctx, key, sizeof(key));
		BENCH_BEGIN("verification") {
			BENCH_ADD(ac_gcm_dec(ctx, msg, &msg_len, sizeof(msg), cipher, cipher_len, msg, SIZES[k], iv, sizeof(iv)));
		}
		BENCH_END;
	}
}

static void bench_encryption(void) {
	unsigned char key[SC_AES128CTR_KEY_LEN];
	authenc_align unsigned char msg[SIZES[0]];
	authenc_align unsigned char cipher[SIZES[0]];
	authenc_align unsigned char iv[AC_GCM_BLOCK_LEN] = { 0 };
	sc_aesctr_ctx_at ctx;
	size_t k;

	for (k = 0; k < sizeof(SIZES) / sizeof(int); k++) {
#undef BENCH
#define BENCH 1280
		BENCH_BEGIN("encryption key setup") {
			BENCH_ADD(sc_aesctr_key(ctx, key, sizeof(key)));
		}
		BENCH_END;
#undef BENCH
#define BENCH 128
		BENCH_BEGIN("encryption") {
			BENCH_ADD(sc_aesctr_enc(ctx, cipher, msg, SIZES[k], iv, sizeof(iv)));
		}
		BENCH_END;
	}
}

#undef BENCH
#define BENCH 2048

#if 0
void ac_gcm_mul_low(dig_t *c, dig_t *a, dig_t *b);

static void bench_gcm_mul(void) {
	authenc_align dig_t a[128/sizeof(dig_t)];
	authenc_align dig_t b[128/sizeof(dig_t)];
	authenc_align dig_t c[128/sizeof(dig_t)];
	BENCH_BEGIN("gcm_mul") {
		BENCH_ADD(ac_gcm_mul_low(c, a, b));
	}
	BENCH_END;
}
#endif

void asmtest(void);

int bench_ac_gcm(void) {
//	bench_gcm_mul();
    BENCH_BEGIN("dummy") {
		BENCH_ADD(dummy());
	}
	BENCH_END;

	bench_encryption();

	bench_authenticated_encryption();

	bench_authentication();

	return 0;
}
#if 0
int main(void) {
    return bench_ac_gcm();
}
#endif