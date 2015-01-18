#include "authenc_ac_gcm.h"

#include <string.h>

/**
 * Multiply two digit vectors in the GCM finite field.
 * @param[out] c	- the product.
 * @param[in] a		- the first operand.
 * @param[in] b		- the second operand.
 */
void ac_gcm_mul_low(dig_t *c, dig_t *a, dig_t *b);

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void ac_gcm_tab_low(dig_t *t, unsigned char *h) {
    const size_t len = AC_GCM_BLOCK_LEN / sizeof(dig_t);
    int i;
	
	memcpy(t, h, AC_GCM_BLOCK_LEN);
    //H^2 -- H^8
    for (i = 1; i < 8; i++) {
        ac_gcm_mul_low(t + i * len, t + (i - 1) * len, t);
    }
}
