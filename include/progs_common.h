#ifndef __PROGS_COMMON_H__
#define __PROGS_COMMON_H__


#include <stdint.h>


#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif

#ifndef __inline
# define __inline                         \
   inline __attribute__((always_inline))
#endif


/**
 * An implementation of memcpy. Data are copied in groups of 4 bytes.
 */
static inline void
bpf_memcpy(void* dst_, void* src_, uint64_t size) {
	uint8_t* dst = (uint8_t*)dst_;
	uint8_t* src = (uint8_t*)src_;
	uint8_t* stop = src + (size & ~(0b111));
	for(; src < stop; src += 8, dst += 8)
		*(uint64_t*)dst = *(uint64_t*)src;
	stop = (uint8_t*)src_ + size;
	for(; src < stop; ++src, ++dst)
		*dst = *src;
}


#endif
