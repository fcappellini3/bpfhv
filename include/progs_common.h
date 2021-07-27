#ifndef __PROGS_COMMON_H__
#define __PROGS_COMMON_H__


#include <stdint.h>

// Define __EBPF__ to let the compiler include or not some features for those sources that are in
// common with the eBPF program and the driver
#define __EBPF__


#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif

#ifndef __inline
# define __inline                         \
   inline __attribute__((always_inline))
#endif


// Data and data types //
typedef uint8_t bool;
typedef uint8_t byte;
#ifndef true
#define true 1U
#endif
#ifndef false
#define false 0U
#endif
#ifndef NULL
#define NULL ((void*)0)
#endif
#ifndef likely
#define likely(x)           __builtin_expect((x), 1)
#endif
#ifndef unlikely
#define unlikely(x)         __builtin_expect((x), 0)
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
