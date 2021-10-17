/**
 * This module provide functions to create and manage trampolines
 */


#ifndef __TRAMPOLINE_REGISTRY_H__
#define __TRAMPOLINE_REGISTRY_H__


#include "types.h"


// Data types
typedef uint64_t (*trampoliine_t)(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);
typedef uint64_t (*trampoline_target_t)(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5, uint64_t magic);


/**
 * Create a new trampoline for "trampoline_target" using "magic" as magic argument (sixth arg)
 */
trampoliine_t
new_trampoline_for(trampoline_target_t trampoline_target, const uint64_t magic);

/**
 * Initiaize this module
 */
void
trampoline_registry_ini(void);

/**
 * Destroy this module
 */
void
trampoline_registry_fini(void);


#endif  //__TRAMPOLINE_REGISTRY_H__
