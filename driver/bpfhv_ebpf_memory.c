#if 0
#include "bpfhv_ebpf_memory.h"
#include <linux/types.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/slab.h>
#endif

/* Driver - BPF program shared memory */
static struct ebpf_memory_descriptor ebpf_memory = {0, 0};

void ebpf_mem_fini(void) {
    if(ebpf_memory.shared_mem_buffer) {
		kfree(ebpf_memory.shared_mem_buffer);
		ebpf_memory.shared_mem_buffer = NULL;
		ebpf_memory.shared_mem_size = 0;
	}
}

void* get_shared_mem(void) {
    if(unlikely(!ebpf_memory.shared_mem_buffer)) {
		ebpf_memory.shared_mem_buffer = kmalloc(SHARED_MEMORY_SIZE, GFP_KERNEL);
		if(unlikely(!ebpf_memory.shared_mem_buffer)) {
			printk(KERN_ERR "get_shared_mem(...) -> ebpf_memory.shared_mem_buffer is null\n");
			return 0;
		}
		ebpf_memory.shared_mem_size = SHARED_MEMORY_SIZE;
	}
	return ebpf_memory.shared_mem_buffer;
}
