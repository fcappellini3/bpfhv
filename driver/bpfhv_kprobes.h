#ifndef __BPFHV_KPROBES_H__
#define __BPFHV_KPROBES_H__


#include "types.h"


/**
 * Initiaize this module
 * return: true if the function succeded, false otherwise
 */
bool
bpfhv_kprobes_ini(void);

/**
 * Finilize this module
 */
void
bpfhv_kprobes_fini(void);


#endif
