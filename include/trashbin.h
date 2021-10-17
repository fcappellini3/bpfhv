/**
 * This module provide basic functionalities to free groups of distinct memory areas all together
 */


#ifndef __TRASHBIN_H__
#define __TRASHBIN_H__


#include "types.h"


// Macros
#define DECLARE_TRASHBIN(NAME, CAPACITY, FREE_FUNCTION) \
    static void* NAME##_elem_array[CAPACITY]; \
    static struct trashbin NAME = { \
        .elem_array = &NAME##_elem_array[0], \
        .free_function = FREE_FUNCTION, \
        .next_index = 0, \
        .capacity = CAPACITY \
    };


/**
 * Trashbin main data structure
 */
struct trashbin {
    void** elem_array;
    void (*free_function)(const void*);
    uint32_t next_index;
    uint32_t capacity;
};


/**
 * Add a new element to the trashbin
 */
static inline bool
add_to_trashbin(struct trashbin* trashbin, void* elem) {
    if(unlikely(!trashbin)) {
        return false;
    }

    if(unlikely(trashbin->next_index == trashbin->capacity)) {
        return false;
    }

    trashbin->elem_array[trashbin->next_index] = elem;
    ++trashbin->next_index;

    return true;
}

/**
 * Empty the trashbin
 */
static inline void
empty_trashbin(struct trashbin* trashbin) {
    uint32_t i;

    for(i = 0; i < trashbin->next_index; ++i) {
        trashbin->free_function(trashbin->elem_array[i]);
    }

    trashbin->next_index = 0;
}



#endif  //__TRASHBIN_H__
