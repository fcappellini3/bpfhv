#ifndef __BPFHV_EBPF_MEMORY_H__
#define __BPFHV_EBPF_MEMORY_H__


#define SHARED_MEMORY_SIZE 1048576 //1MiB


/*
 * When compiling user-space code include <stdint.h>,
 * when compiling kernel-space code include <linux/types.h>
 */
#ifdef __KERNEL__
#include <linux/types.h>
#else  /* !__KERNEL__ */
#include <stdint.h>
#endif /* !__KERNEL__ */


/* Driver - BPF program shared memory */
struct ebpf_memory_descriptor {
	void* shared_mem_buffer;
	uint64_t shared_mem_size;
};


void ebpf_mem_ini(void);
void ebpf_mem_fini(void);
void* get_shared_mem(void);


#endif
