#include "authenc_ac_gcm.h"

#include <string.h>

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#define GCM_DIGS (AC_GCM_BLOCK_LEN / sizeof(dig_t))
#define GCM_BITS 128
#define DIGIT (sizeof(dig_t) * 8)
#define MASK(B)				(((dig_t)1 << (B)) - 1)

#ifndef AC_GCM_REFLC
/** Table used to reflect the bits inside a byte. */
static const unsigned char byte_table[] = {
		0x0, 0x80, 0x40, 0xc0, 0x20,
		0xa0, 0x60, 0xe0, 0x10, 0x90, 0x50, 0xd0, 0x30, 0xb0, 0x70,
		0xf0, 0x8, 0x88, 0x48, 0xc8, 0x28, 0xa8, 0x68, 0xe8, 0x18,
		0x98, 0x58, 0xd8, 0x38, 0xb8, 0x78, 0xf8, 0x4, 0x84, 0x44,
		0xc4, 0x24, 0xa4, 0x64, 0xe4, 0x14, 0x94, 0x54, 0xd4, 0x34,
		0xb4, 0x74, 0xf4, 0xc, 0x8c, 0x4c, 0xcc, 0x2c, 0xac, 0x6c,
		0xec, 0x1c, 0x9c, 0x5c, 0xdc, 0x3c, 0xbc, 0x7c, 0xfc, 0x2,
		0x82, 0x42, 0xc2, 0x22, 0xa2, 0x62, 0xe2, 0x12, 0x92, 0x52,
		0xd2, 0x32, 0xb2, 0x72, 0xf2, 0xa, 0x8a, 0x4a, 0xca, 0x2a,
		0xaa, 0x6a, 0xea, 0x1a, 0x9a, 0x5a, 0xda, 0x3a, 0xba, 0x7a,
		0xfa, 0x6, 0x86, 0x46, 0xc6, 0x26, 0xa6, 0x66, 0xe6, 0x16,
		0x96, 0x56, 0xd6, 0x36, 0xb6, 0x76, 0xf6, 0xe, 0x8e, 0x4e,
		0xce, 0x2e, 0xae, 0x6e, 0xee, 0x1e, 0x9e, 0x5e, 0xde, 0x3e,
		0xbe, 0x7e, 0xfe, 0x1, 0x81, 0x41, 0xc1, 0x21, 0xa1, 0x61,
		0xe1, 0x11, 0x91, 0x51, 0xd1, 0x31, 0xb1, 0x71, 0xf1, 0x9,
		0x89, 0x49, 0xc9, 0x29, 0xa9, 0x69, 0xe9, 0x19, 0x99, 0x59,
		0xd9, 0x39, 0xb9, 0x79, 0xf9, 0x5, 0x85, 0x45, 0xc5, 0x25,
		0xa5, 0x65, 0xe5, 0x15, 0x95, 0x55, 0xd5, 0x35, 0xb5, 0x75,
		0xf5, 0xd, 0x8d, 0x4d, 0xcd, 0x2d, 0xad, 0x6d, 0xed, 0x1d,
		0x9d, 0x5d, 0xdd, 0x3d, 0xbd, 0x7d, 0xfd, 0x3, 0x83, 0x43,
		0xc3, 0x23, 0xa3, 0x63, 0xe3, 0x13, 0x93, 0x53, 0xd3, 0x33,
		0xb3, 0x73, 0xf3, 0xb, 0x8b, 0x4b, 0xcb, 0x2b, 0xab, 0x6b,
		0xeb, 0x1b, 0x9b, 0x5b, 0xdb, 0x3b, 0xbb, 0x7b, 0xfb, 0x7,
		0x87, 0x47, 0xc7, 0x27, 0xa7, 0x67, 0xe7, 0x17, 0x97, 0x57,
		0xd7, 0x37, 0xb7, 0x77, 0xf7, 0xf, 0x8f, 0x4f, 0xcf, 0x2f,
		0xaf, 0x6f, 0xef, 0x1f, 0x9f, 0x5f, 0xdf, 0x3f, 0xbf, 0x7f,
		0xff
};
#endif

static void addn_low(dig_t *c, dig_t *a, dig_t *b) {
	size_t i;

	for (i = 0; i < GCM_DIGS; i++, a++, b++, c++) {
		(*c) = (*a) ^ (*b);
	}
}

static dig_t lshb_low(dig_t *c, dig_t *a, int bits) {
	size_t i;
	dig_t r, carry, mask, shift;

	/* Prepare the bit mask. */
	shift = DIGIT - bits;
	carry = 0;
	mask = MASK(bits);
	for (i = 0; i < GCM_DIGS; i++, a++, c++) {
		/* Get the needed least significant bits. */
		r = ((*a) >> shift) & mask;
		/* Shift left the operand. */
		*c = ((*a) << bits) | carry;
		/* Update the carry. */
		carry = r;
	}
	return carry;
}

#ifdef AC_GCM_REFLC

static dig_t rshb_low(dig_t *c, dig_t *a, int bits) {
	int i;
	dig_t r, carry, mask, shift;

	c += GCM_DIGS - 1;
	a += GCM_DIGS - 1;
	/* Prepare the bit mask. */
	mask = ((dig_t)1 << (dig_t)bits) - 1;
	shift = DIGIT - bits;
	carry = 0;
	for (i = GCM_DIGS - 1; i >= 0; i--, a--, c--) {
		/* Get the needed least significant bits. */
		r = (*a) & mask;
		/* Shift left the operand. */
		*c = ((*a) >> bits) | (carry << shift);
		/* Update the carry. */
		carry = r;
	}
	return carry;
}

static void rdcn(dig_t *c, dig_t *a) {
	dig_t t[GCM_DIGS];
	dig_t d;

	d = lshb_low(a, a, 1);
	lshb_low(a + GCM_DIGS, a + GCM_DIGS, 1);
	a[GCM_DIGS] ^= d;

	d = a[0];
	d = (d << (DIGIT - 1)) ^ (d << (DIGIT - 2)) ^ (d << (DIGIT - 7));
	a[GCM_DIGS - 1] ^= d;
	addn_low(c, a + GCM_DIGS, a);
	rshb_low(t, a, 1);
	addn_low(c, c, t);
	rshb_low(t, a, 2);
	addn_low(c, c, t);
	rshb_low(t, a, 7);
	addn_low(c, c, t);
}

#else

static void rdcn(dig_t *c, dig_t *a) {
	dig_t t[GCM_DIGS];
	dig_t d;

	d = a[2 * GCM_DIGS - 1];
	d = (d >> (DIGIT - 1)) ^ (d >> (DIGIT - 2)) ^ (d >> (DIGIT - 7));
	a[GCM_DIGS] ^= d;
	addn_low(c, a, a + GCM_DIGS);
	lshb_low(t, a + GCM_DIGS, 1);
	addn_low(c, c, t);
	lshb_low(t, a + GCM_DIGS, 2);
	addn_low(c, c, t);
	lshb_low(t, a + GCM_DIGS, 7);
	addn_low(c, c, t);
}

#endif

static void muln(dig_t *c, dig_t *a, dig_t *b) {
	dig_t u0, u1, carry, *tmpa, *tmpc;
	size_t i;
	int k;

	dig_t (*table)[GCM_DIGS + 1] = (dig_t (*)[GCM_DIGS + 1]) b;

	for (i = 0; i < 2 * GCM_DIGS; i++) {
		c[i] = 0;
	}

	for (k = sizeof(dig_t) - 1; k >= 0; k -= 1) {
		tmpa = a;
		tmpc = c;
		for (i = 0; i < GCM_DIGS; i++, tmpa++, tmpc++) {
			u0 = (*tmpa >> (8*k)) & 0x0F;
			u1 = ((*tmpa >> (8*k+4)) & 0x0F) + 16;
			addn_low(tmpc, tmpc, table[u0]);
			*(tmpc + GCM_DIGS) ^= table[u0][GCM_DIGS];
			addn_low(tmpc, tmpc, table[u1]);
			*(tmpc + GCM_DIGS) ^= table[u1][GCM_DIGS];
		}
		if (k > 0) {
			carry = lshb_low(c, c, 8);
			lshb_low(c + GCM_DIGS, c + GCM_DIGS, 8);
			c[GCM_DIGS] ^= carry;
		}
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void ac_gcm_tab_low(dig_t *t, unsigned char *h) {
	dig_t (*table)[GCM_DIGS + 1] = (dig_t (*)[GCM_DIGS + 1]) t;
	dig_t r0, r1, r2, r4, r8, u;
	size_t i;
	dig_t *b = (dig_t *) h;

	memset(table, 0, 16 * sizeof(*table));

	u = 0;
	for (i = 0; i < GCM_DIGS; i++) {
		r1 = r0 = b[i];
		r2 = (r0 << 1) | (u >> (DIGIT - 1));
		r4 = (r0 << 2) | (u >> (DIGIT - 2));
		r8 = (r0 << 3) | (u >> (DIGIT - 3));
		table[0][i] = 0;
		table[1][i] = r1;
		table[2][i] = r2;
		table[3][i] = r1 ^ r2;
		table[4][i] = r4;
		table[5][i] = r1 ^ r4;
		table[6][i] = r2 ^ r4;
		table[7][i] = r1 ^ r2 ^ r4;
		table[8][i] = r8;
		table[9][i] = r1 ^ r8;
		table[10][i] = r2 ^ r8;
		table[11][i] = r1 ^ r2 ^ r8;
		table[12][i] = r4 ^ r8;
		table[13][i] = r1 ^ r4 ^ r8;
		table[14][i] = r2 ^ r4 ^ r8;
		table[15][i] = r1 ^ r2 ^ r4 ^ r8;
		u = r1;
	}

	if (u > 0) {
		r2 = u >> (DIGIT - 1);
		r4 = u >> (DIGIT - 2);
		r8 = u >> (DIGIT - 3);
		table[0][GCM_DIGS] = table[1][GCM_DIGS] = 0;
		table[2][GCM_DIGS] = table[3][GCM_DIGS] = r2;
		table[4][GCM_DIGS] = table[5][GCM_DIGS] = r4;
		table[6][GCM_DIGS] = table[7][GCM_DIGS] = r2 ^ r4;
		table[8][GCM_DIGS] = table[9][GCM_DIGS] = r8;
		table[10][GCM_DIGS] = table[11][GCM_DIGS] = r2 ^ r8;
		table[12][GCM_DIGS] = table[13][GCM_DIGS] = r4 ^ r8;
		table[14][GCM_DIGS] = table[15][GCM_DIGS] = r2 ^ r4 ^ r8;
	}

	for (i = 0; i < 16; i++) {
		dig_t carry = lshb_low(table[i+16], table[i], 4);
		table[i+16][GCM_DIGS] = carry ^ (table[i][GCM_DIGS] << 4);
	}
}

void ac_gcm_mul_low(dig_t *c, dig_t *a, dig_t *b) {
	authenc_align dig_t t[GCM_DIGS*2];

	muln(t, a, b);
	rdcn(c, t);
}

/**
 * Convert byte stream to GCM representation.
 *
 * Since GCM treats the bits inside a byte in reverse order, we must convert it
 * to a suitable representation.
 *
 * @param[out] c			- the output block.
 * @param[in] a				- the input block.
 */
#if defined(AC_GCM_REFLC)
void ac_gcm_convert_low(unsigned char *c, const unsigned char *a) {
	bc_t t;
	int i, j;
#ifdef BIGED
	dig_t *ad = (dig_t *) a;
	dig_t *td = (dig_t *) t;
	for (i = 0; i < AC_GCM_BLOCK_LEN / sizeof(dig_t); i += 1) {
		td[AC_GCM_BLOCK_LEN / sizeof(dig_t) - i - 1] = ad[i];
	}
#else
	for (i = 0; i < AC_GCM_BLOCK_LEN; i += sizeof(dig_t)) {
		for (j = 0; j < sizeof(dig_t); j++) {
			t[(AC_GCM_BLOCK_LEN - i - sizeof(dig_t)) + j] = a[i + (sizeof(dig_t) - j - 1)];
		}
	}
#endif
	memcpy(c, t, AC_GCM_BLOCK_LEN);
}
#else
void ac_gcm_convert_low(unsigned char *c, const unsigned char *a) {
	int i;
#ifdef BIGED
	uint32_t *p = (uint32_t *) block;
	for (i = 0; i < AC_GCM_BLOCK_LEN / sizeof(uint32_t); i++) {
		p[i] = util_conv_little(p[i]);
	}
#endif
	for (i = 0; i < AC_GCM_BLOCK_LEN; i++) {
		c[i] = byte_table[a[i]];
	}
}
#endif
