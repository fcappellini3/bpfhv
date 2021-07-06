/**
 * This module contains utility functions for BPF programs
*/


#include <stdint.h>


#define BPF_STORE_STRING(WHERE, STRING_LITERAL) \
    bpf_memcpy(WHERE, STRING_LITERAL, sizeof(STRING_LITERAL))


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
