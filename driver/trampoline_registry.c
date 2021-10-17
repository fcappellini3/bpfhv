#include "trampoline_registry.h"
#include <linux/module.h>
#include <linux/gfp.h>
#include <linux/vmalloc.h>
#include <linux/kallsyms.h>
//#include <asm-generic/set_memory.h>


// Prototypes
int set_memory_x(unsigned long addr, int numpages);   // Exported by mm/pageattr.c
int set_memory_nx(unsigned long addr, int numpages);  // Exported by mm/pageattr.c


// Constants
#define TRAMPOLINE_MEM_AREA_SIZE 4096U   // Has to be multiple of 4096
#define TRAMPOLINE_CODE_SIZE 26U
#define MAX_TRAMPOLINES (TRAMPOLINE_MEM_AREA_SIZE / TRAMPOLINE_CODE_SIZE)   // 157


// Data
static uint32_t trampoline_count = 0;
static struct {
    byte trampoline_mem[TRAMPOLINE_MEM_AREA_SIZE];
} areas __attribute__((aligned(4096)));
static int (*set_memory_ro_ptr)(unsigned long addr, int numpages) = NULL;
static int (*set_memory_rw_ptr)(unsigned long addr, int numpages) = NULL;


/**
 * Set memory RO
 */
static inline int
set_memory_ro(unsigned long addr, int numpages) {
    if(unlikely(!set_memory_ro_ptr)) {
        return -1;
    }
    return set_memory_ro_ptr(addr, numpages);
}

/**
 * Set memory RW
 */
static inline int
set_memory_rw(unsigned long addr, int numpages) {
    if(unlikely(!set_memory_rw_ptr)) {
        return -1;
    }
    return set_memory_rw_ptr(addr, numpages);
}

/**
 * Compose a trampoline at address "where" for function "trampoline_target" using "magic" as magic
 * argument (sixth arg)
 */
static inline void
compose_trampoline(byte* where, trampoline_target_t trampoline_target, const uint64_t magic) {
    /*
     *    f3 0f 1e fa             endbr64
     *    49 b9 ef be ad de ef    movabs $0xdeadbeefdeadbeef,%r9
     *    be ad de
     *    48 b8 dd cc bb aa dd    movabs $0xaabbccddaabbccdd,%rax
     *    cc bb aa
     *    ff e0                   jmpq  *%rax
     */

    *(uint32_t*)where = 0xfa1e0ff3U;
    where[4] = 0x49;
    where[5] = 0xb9;
    *(uint64_t*)(where + 6) = magic;
    where[14] = 0x48;
    where[15] = 0xb8;
    *(uint64_t*)(where + 16) = (uint64_t)trampoline_target;
    where[24] = 0xff;
    where[25] = 0xe0;
}

/**
 * Docstring in trampoline_registry.h
 */
trampoliine_t
new_trampoline_for(trampoline_target_t trampoline_target, const uint64_t magic) {
    byte* trampoline_code;
    int err;

    // Check if there is enouth space for trampolines
    if(trampoline_count >= MAX_TRAMPOLINES) {
        return NULL;
    }

    // Temporarily set the trampoline area RW
    err = set_memory_rw(
        (unsigned long)&areas.trampoline_mem[0], (TRAMPOLINE_MEM_AREA_SIZE >> 12)
    );
    if(unlikely(err)) {
        printk(KERN_ERR "%s() -> set_memory_rw() returned %d\n", __PRETTY_FUNCTION__, err);
        return NULL;
    }

    // Compose the trampoline
    trampoline_code = &areas.trampoline_mem[0] + (trampoline_count * TRAMPOLINE_CODE_SIZE);
    ++trampoline_count;
    compose_trampoline(trampoline_code, trampoline_target, magic);

    // Set the trampoline area RO again
    err = set_memory_ro(
        (unsigned long)&areas.trampoline_mem[0], (TRAMPOLINE_MEM_AREA_SIZE >> 12)
    );
    if(unlikely(err)) {
        printk(KERN_ERR "%s() -> set_memory_ro() returned %d\n", __PRETTY_FUNCTION__, err);
    }

    return (trampoliine_t)trampoline_code;
}

/**
 * Docstring in trampoline_registry.h
 */
void
trampoline_registry_ini() {
    int err;

    // Lookup necessary symbols
    set_memory_ro_ptr = (int (*)(unsigned long addr, int numpages))kallsyms_lookup_name("set_memory_ro");
    set_memory_rw_ptr = (int (*)(unsigned long addr, int numpages))kallsyms_lookup_name("set_memory_rw");

    // Set the trampoline area as readonly and executable
    err = set_memory_x(
        (unsigned long)&areas.trampoline_mem[0], (TRAMPOLINE_MEM_AREA_SIZE >> 12)
    );
    if(unlikely(err)) {
        printk(KERN_ERR "%s() -> set_memory_x() returned %d\n", __PRETTY_FUNCTION__, err);
    }
    err = set_memory_ro(
        (unsigned long)&areas.trampoline_mem[0], (TRAMPOLINE_MEM_AREA_SIZE >> 12)
    );
    if(unlikely(err)) {
        printk(KERN_ERR "%s() -> set_memory_ro() returned %d\n", __PRETTY_FUNCTION__, err);
    }

    // Other stuff
    trampoline_count = 0;
}

/**
 * Docstring in trampoline_registry.h
 */
void
trampoline_registry_fini() {
    // Set the trampoline area as not executable
    int err = set_memory_nx(
        (unsigned long)&areas.trampoline_mem[0], (TRAMPOLINE_MEM_AREA_SIZE >> 12)
    );
    if(unlikely(err)) {
        printk(KERN_ERR "%s() -> set_memory_nx() returned %d\n", __PRETTY_FUNCTION__, err);
    }
}


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Federico Cappellini");
