#ifndef AUTHENC_UTIL_H_
#define AUTHENC_UTIL_H_

#include <stdlib.h>
#include <stdint.h>


void authenc_xor(unsigned char *c, const unsigned char *a, const unsigned char *b, size_t len);

void authenc_inc32(unsigned char *a, size_t val, size_t len);

void authenc_read32(uint32_t *c, const unsigned char *a);

void authenc_write32(unsigned char *c, uint32_t a);

void authenc_read64(uint64_t *c, const unsigned char *a);

void authenc_write64(unsigned char *c, uint64_t a);

int authenc_cmp_const(const void * a, const void *b, const size_t size);

#endif /* AUTHENC_UTIL_H_ */
