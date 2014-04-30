#include "authenc_ac_gcm.h"
#include "authenc_util.h"

#include <string.h>
#define AC_GCM_REFLC

#define GCM_DIGS (AC_GCM_BLOCK_LEN / sizeof(dig_t))
#define DIGIT (sizeof(dig_t) * 8)
#define MASK(B)				(((dig_t)1 << (B)) - 1)

void ac_gcm_convert_low(unsigned char *c, const unsigned char *a);

void ac_gcm_mul_low(dig_t *c, dig_t *a, dig_t *b);


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

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void ac_gcm_tab_low(dig_t *t, unsigned char *h) {
	memcpy(t, h, AC_GCM_BLOCK_LEN);

#ifdef AC_GCM_REFLC
	dig_t d;
	d = lshb_low(t, t, 1);
	t[GCM_DIGS - 1] ^= (d << (DIGIT - 1)) ^ (d << (DIGIT - 2)) ^ (d << (DIGIT - 7));
	t[0] ^= d;
#endif
}

void ac_gcm_ghash_low(unsigned char *last_y, const dig_t *table, const unsigned char *input, size_t len) {
	authenc_align unsigned char t[AC_GCM_BLOCK_LEN];
	size_t i;

	for (i = 0; i < len; i += AC_GCM_BLOCK_LEN) {
		//xor (field addition)
		ac_gcm_convert_low(t, input + i);
		authenc_xor(last_y, last_y, t, AC_GCM_BLOCK_LEN);
		//binary field multiplication
		ac_gcm_mul_low((dig_t *) last_y, (dig_t *) last_y, (dig_t *) table);
	}
}
