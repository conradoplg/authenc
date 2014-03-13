#include "authenc_ac_gcm.h"

#include <string.h>


/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void ac_gcm_tab_low(dig_t *t, unsigned char *h) {
	memcpy(t, h, AC_GCM_BLOCK_LEN);
}
