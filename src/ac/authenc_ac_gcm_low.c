#include "authenc_ac_gcm.h"

#include <string.h>

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#define GCM_DIGS (AC_GCM_BLOCK_LEN / sizeof(dig_t))
#define GCM_BITS 128
#define DIGIT (sizeof(dig_t) * 8)
#define MASK(B)				(((dig_t)1 << (B)) - 1)

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
