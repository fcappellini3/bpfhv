#ifndef __TYPES_H__
#define __TYPES_H__


/*
 * When compiling user-space code include <stdint.h>,
 * when compiling kernel-space code include <linux/types.h>
 */
#ifdef __KERNEL__
#include <linux/types.h>
#else  /* !__KERNEL__ */
#include <stdint.h>
#endif /* !__KERNEL__ */


// Data types
typedef uint8_t byte;
typedef uint32_t ipv4_t;      // big endian 32 bit
typedef uint16_t net_port_t;  // big endian 16 bit
#if !defined(bool) && !defined(__KERNEL__)
#define bool uint8_t
#endif
#ifndef true
#define true 1U
#endif
#ifndef false
#define false 0U
#endif
#ifndef NULL
#define NULL ((void*)0)
#endif

struct buffer_descriptor {
    void* buff;
    uint64_t len;
};


// Macros
#ifndef __inline
#define __inline \
   inline __attribute__((always_inline))
#endif


#endif
