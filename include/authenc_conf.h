#ifndef AUTHENC_CONF_H_
#define AUTHENC_CONF_H_

#include <stdint.h>


#ifndef __STDC_LIB_EXT1__
  typedef int errno_t;
#endif

#define authenc_align __attribute__ ((aligned (8)))

typedef uint64_t dig_t;

#endif
