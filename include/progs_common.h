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
#define NOT_FOUND 0xFFFFFFFFU


/**
 * An implementation of memcpy for BPF progs. Data are copied in groups of 4 bytes.
 */
static __inline void
bpf_memcpy(void* dst_, const void* src_, uint64_t size) {
	uint8_t* dst = (uint8_t*)dst_;
	uint8_t* src = (uint8_t*)src_;
	uint8_t* stop = src + (size & ~(0b111));
	for(; src < stop; src += 8, dst += 8)
		*(uint64_t*)dst = *(uint64_t*)src;
	stop = (uint8_t*)src_ + size;
	for(; src < stop; ++src, ++dst)
		*dst = *src;
}

/**
 * An implementation of strlen for BPF progs
 */
static __inline uint32_t
bpf_strlen(const char* str) {
    uint32_t len = 0;

    if(unlikely(!str)) {
        return 0;
    }

    for(; *str != '\0'; ++str) {
        ++len;
    }

    return len;
}

/**
 * Find "what" inside "where". This is the "BPF" version of the helper function "find".
 * It performs much worse, so use it only for testing pourposes.
 * return: index of "what" inside "where" or NOT_FOUND if not found
 */
static __inline uint32_t
bpf_find(const byte* where, const uint32_t where_size, const byte* what, const uint32_t what_size) {
    uint32_t i, j, stop;
    bool found;

    if(what_size > where_size)
        return NOT_FOUND;

    stop = where_size - what_size;
    for(i = 0; i < stop; ++i) {
        found = true;
        for(j = 0; j < what_size; ++j) {
            if(where[i+j] != what[j]) {
                found = false;
                break;
            }
        }
        if(found) {
            return i;
        }
    }

    return NOT_FOUND;
}

/**
 * An implementation of strstr for BPF progs
 */
static __inline char*
bpf_strstr(const char* where, const char* what) {
    uint32_t index;

    if(unlikely(!where || !what)) {
        return NULL;
    }

    index = bpf_find(
        (byte*)where, bpf_strlen(where),
        (byte*)what, bpf_strlen(what)
    );

    if(likely(index == NOT_FOUND)) {
        return NULL;
    }

    return (char*)(where + index);
}


#endif
