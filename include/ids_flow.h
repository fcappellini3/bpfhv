#ifndef __IDS_FLOW_H__
#define __IDS_FLOW_H__


#ifdef __EBPF__
#include <stdint.h>
#include "progs_common.h"
#else
typedef uint8_t byte;
#endif


// Data types
typedef uint32_t ipv4_t;  // big endian 32 bit
typedef uint32_t flow_key_t;
#ifndef true
#define true 1U
#endif
#ifndef false
#define false 0U
#endif


// Macros
#define NEXT_TCP_ORDER(ord) (((ord) + 1) & 0b1111111111111)
#define STORE_PKT_SUCCESS  0
#define STORE_PKT_ERROR    1
#define STORE_PKT_REJECTED 2
#ifndef __inline
# define __inline                         \
   inline __attribute__((always_inline))
#endif


/**
 * A flow is a collection of flow element (struct flow_elem).
 * Each flow_elem represent a section of the flow.
 */
struct flow_elem {
    struct flow_elem* next;
    void* buff;
    uint32_t len;
    uint32_t order;
};


/**
 * Each flow is identified by a flow identificator (struct flow_id)
 */
struct flow_id {
    ipv4_t src_ip;
    ipv4_t dest_ip;
    uint16_t src_port;
    uint16_t dest_port;
    uint8_t protocol;
}__attribute__((packed));


/**
 * Main flow data structure. A struct flow represent a window on the communication between 2 hosts
 * in a single direction. When a flow is exceding max_size, the first part is removed (window
 * on the communication).
 */
struct flow {
    struct flow_elem* head;
    struct flow_elem* tail;
    void* reserved;
    struct flow_id flow_id;
    uint32_t size;
    uint32_t max_size;
    uint32_t elem_count;
    bool ordered;
};


/**
 * Data structure that help the user travel a flow
 */
struct flow_iter {
    struct flow_elem* current_flow_elem;
    uint32_t index;
};


// Prototypes
#ifndef __EBPF__

/**
 * Initiaize this module
 */
void ids_flow_ini(void);

/**
 * Finilize this module
 */
void ids_flow_fini(void);

/**
 * Compare 2 struct flow_id
 * return: true if the flow_ids are equal
 */
static bool flow_id_equal(const struct flow_id* flow_a, const struct flow_id* flow_b);

/**
 * Get a flow by its flow_id
 */
static struct flow* get_flow(const struct flow_id* flow_id);

/**
 * Create a new flow
 */
static struct flow*
create_flow(const struct flow_id* flow_id, const bool ordered, const uint32_t max_size);

/**
 * Delete a flow and free memory
 */
static bool delete_flow(struct flow_id* flow_id);

/**
 * Store a struct flow_elem (a packet) into a flow.
 * flow: the flow in which the packet has to be stored.
 * buff: packet data (you may want to store only the payload)
 * len: packet len (related to data)
 * order: packet sequence number or other ordering policy
 * return: STORE_PKT_SUCCESS, STORE_PKT_ERROR or STORE_PKT_REJECTED
 */
static uint32_t store_pkt(struct flow* flow, void* buff, const uint32_t len, const uint32_t order);

#endif

/**
 * Initialization function for a struct flow_iter*.
 * flow: the flow for which the iter has to be initialized.
 * return: pointer to the first byte of the flow.
 */
static __inline byte*
iter_init(struct flow_iter* iter, struct flow* flow) {
    iter->current_flow_elem = flow->head;
    iter->index = 0;
    if(unlikely(!iter->current_flow_elem || !iter->current_flow_elem->len))
        return NULL;
    return (byte*)iter->current_flow_elem->buff;
}

/**
 * Get the pointer to the next byte of the iterator
 * return: the next byte or NULL if no more bytes are available
 */
static __inline byte*
iter_next(struct flow_iter* iter) {
    if(!iter->current_flow_elem)
        return NULL;

    ++iter->index;

    while(unlikely(iter->index >= iter->current_flow_elem->len)) {
        if(!iter->current_flow_elem->next)
            return NULL;
        iter->current_flow_elem = iter->current_flow_elem->next;
        iter->index = 0;
    }
    return (byte*)iter->current_flow_elem->buff + iter->index;
}


#endif
