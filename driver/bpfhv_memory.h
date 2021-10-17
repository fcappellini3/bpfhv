/**
 * Definition and utility functions for BPFHV memory system.
 * This module seems to be a bit pointless: is it just an over-engineered source code file?
 * Maybe not, because now struct bpfhv_shared_mem_des is quite simple, but it could be much more
 * complex in future. For example, it will be possible to allocate memory partially RW and partially
 * RO to store in the RO area information that cannot be changed by the BPF program.
 */


#ifndef __BPFHV_EBPF_MEMORY_H__
#define __BPFHV_EBPF_MEMORY_H__


#include "types.h"
#include "trashbin.h"
#include <linux/slab.h>


#define DEFAULT_SHARED_MEMORY_SIZE 1048576  //1MiB


/* Driver - BPF program shared memory */
struct bpfhv_shared_mem_des {
	void* buffer;
	uint64_t size;
};


/**
 * Initialization of the struct bpfhv_shared_mem_des to NULL (no reserved memory)
 */
static inline void
bpfhv_shared_mem_des_ini(struct bpfhv_shared_mem_des* des) {
	des->buffer = NULL;
	des->size = 0;
}

/**
 * Init and alloc struct bpfhv_shared_mem_des.
 * return: true in case of success, false otherwise.
 */
static inline bool
bpfhv_shared_mem_des_alloc(struct bpfhv_shared_mem_des* des, const uint64_t size) {
	des->buffer = kmalloc(size, GFP_KERNEL);
	if(unlikely(!des->buffer)) {
		des->size = 0;
		return false;
	}
	des->size = size;
	return true;
}

/**
 * Call bpfhv_shared_mem_des_alloc with default values
 */
static inline bool
bpfhv_shared_mem_des_default_alloc(struct bpfhv_shared_mem_des* des) {
	return bpfhv_shared_mem_des_alloc(des, DEFAULT_SHARED_MEMORY_SIZE);
}

/**
 * Add bpfhv_shared_mem_des to trashbin
 */
static inline bool
bpfhv_shared_mem_des_add_to_trashbin(struct bpfhv_shared_mem_des* des, struct trashbin* trashbin) {
	return add_to_trashbin(trashbin, des->buffer);
}


#endif
