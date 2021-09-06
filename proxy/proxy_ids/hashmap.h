/**
 * Module that offer a simple header-only hashmap
 */


#ifndef __HASHMAP_H__
#define __HASHMAP_H__


#include "types.h"
#include <stdlib.h>


// Check if h_key_t and h_value_t are defined
#ifndef h_key_t
#error "hashmap.h included, but h_key_t not defined"
#endif
#ifndef h_value_t
#error "hashmap.h included, but h_value_t not defined"
#endif


struct hashmap {
    uint32_t hashtable_size;
    struct h_node** hashtable;
    uint32_t (*hash)(const h_key_t* h_key);
    bool (*key_compare)(const h_key_t* key_a, const h_key_t* key_b);
};


#define HASHMAP(SIZE, HASH_FUNCTION, KEY_COMPARE_FUNCTION) \
    {SIZE, 0, HASH_FUNCTION, KEY_COMPARE_FUNCTION}

#define DECLARE_HASHMAP(NAME, SIZE, HASH_FUNCTION, KEY_COMPARE_FUNCTION) \
    static struct hashmap NAME = HASHMAP(SIZE, HASH_FUNCTION, KEY_COMPARE_FUNCTION)


struct h_node {
    struct h_node* next;
    h_key_t key;
    h_value_t value;
};


/**
 * Initialize the hashmap
 */
static void
hashmap_ini(struct hashmap* hashmap) {
    uint32_t i;
    hashmap->hashtable = malloc(sizeof(struct h_node*) * hashmap->hashtable_size);
    for(i = 0; i < hashmap->hashtable_size; ++i)
        hashmap->hashtable[i] = 0;
}

/**
 * Destroy the hashmap
 */
static void
hashmap_fini(struct hashmap* hashmap) {
    if(hashmap->hashtable) {
        free(hashmap->hashtable);
    }
    hashmap->hashtable = 0;
}

/**
 * Store value at key key
 */
static void
h_store(struct hashmap* hashmap, const h_key_t key, h_value_t value) {
    uint32_t index = hashmap->hash(&key);
    struct h_node* h_node = malloc(sizeof(struct h_node));
    h_node->key = key;
    h_node->value = value;
    struct h_node* old_head = hashmap->hashtable[index];
    h_node->next = old_head;
    hashmap->hashtable[index] = h_node;
}

/**
 * Retrieve stored value for key key
 */
static h_value_t
h_get(struct hashmap* hashmap, const h_key_t key) {
    struct h_node* ptr;
    uint32_t index = hashmap->hash(&key);
    for(ptr = hashmap->hashtable[index]; ptr; ptr = ptr->next) {
        if(hashmap->key_compare(&ptr->key, &key))
            return ptr->value;
    }
    return 0;
}

/**
 * Delete (key, <value associated with key>) from the hashmap
 */
static bool
h_delete(struct hashmap* hashmap, const h_key_t key) {
    struct h_node* ptr;
    struct h_node* prev = 0;
    uint32_t index = hashmap->hash(&key);
    for(ptr = hashmap->hashtable[index]; ptr; prev = ptr, ptr = ptr->next) {
        if(hashmap->key_compare(&ptr->key, &key)) {
            if(!prev) {
                hashmap->hashtable[index] = ptr->next;
            } else {
                prev->next = ptr->next;
            }
            free(ptr);
            return true;
        }
    }

    return false;
}


#endif
