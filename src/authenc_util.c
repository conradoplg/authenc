#include "authenc_util.h"


void authenc_xor(unsigned char *c, unsigned char *a, unsigned char *b,
		size_t len) {
	size_t i;

	for (i = 0; i < len; i++, a++, b++, c++) {
		(*c) = (*a) ^ (*b);
	}
}

void authenc_inc32(unsigned char *a, size_t len) {
	uint32_t d;

	if (len < sizeof(uint32_t)) {
		return;
	}

	authenc_read32(&d, a + (len - sizeof(uint32_t)));
	d += 1;
	authenc_write32(a + (len - sizeof(uint32_t)), d);
}

void authenc_read32(uint32_t *c, const unsigned char *a) {
	*c = a[3] | (a[2] << 8) | (a[1] << 16) | (a[0] << 24);
}

void authenc_write32(unsigned char *c, uint32_t a) {
	c[3] = a & 0xFF;
	c[2] = (a >> 8) & 0xFFu;
	c[1] = (a >> 16) & 0xFFu;
	c[0] = (a >> 24) & 0xFFu;
}

void authenc_read64(uint64_t *c, const unsigned char *a) {
	uint32_t low, high;
	authenc_read32(&high, a);
	authenc_read32(&low, a + sizeof(high));
	*c = (uint64_t) low | ((uint64_t) high) << 32;
}

void authenc_write64(unsigned char *c, uint64_t a) {
	authenc_write32(c, (a >> 32) & 0xFFFFu);
	authenc_write32(c + sizeof(uint32_t), a & 0xFFFFu);
}

int authenc_cmp_const(const void * a, const void *b, const size_t size) {
	const unsigned char *_a = (const unsigned char *) a;
	const unsigned char *_b = (const unsigned char *) b;
	unsigned char result = 0;
	size_t i;

	for (i = 0; i < size; i++) {
		result |= _a[i] ^ _b[i];
	}

	return result; /* returns 0 if equal, nonzero otherwise */
}
