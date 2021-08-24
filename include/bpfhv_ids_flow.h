#ifndef __IDS_FLOW_H__
#define __IDS_FLOW_H__


#include "types.h"


#ifndef __EBPF__
#include <net/sock.h>
#endif


// Data types
typedef uint32_t flow_key_t;


// Macros
#ifndef _likely
#define _likely(x)           __builtin_expect((x), 1)
#endif
#ifndef _unlikely
#define _unlikely(x)         __builtin_expect((x), 0)
#endif
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
};


/**
 * Each flow is identified by a flow identificator (struct flow_id)
 */
struct flow_id {
    ipv4_t src_ip;
    ipv4_t dest_ip;
    net_port_t src_port;
    net_port_t dest_port;
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
    bool recording_enabled;
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
 * Get a flow by its flow_id
 */
struct flow* get_flow(const struct flow_id* flow_id);

/**
 * Create a new flow
 */
struct flow*
create_flow(const struct flow_id* flow_id, const bool ordered, const uint32_t max_size);

/**
 * Delete a flow and free memory
 */
bool delete_flow(struct flow_id* flow_id);

/**
 * Store a struct flow_elem (a packet) into a flow.
 * flow: the flow in which the packet has to be stored.
 * buff: packet data (you may want to store only the payload)
 * len: packet len (related to data)
 * return: STORE_PKT_SUCCESS, STORE_PKT_ERROR or STORE_PKT_REJECTED
 */
uint32_t store_pkt(struct flow* flow, void* buff, const uint32_t len);

/**
 * Replacement for inet_recvmsg(struct socket *sock, struct msghdr *msg, size_t size, int flags).
 * It does the same job, but store packets if needed
 */
int inet_recvmsg_replacement(struct socket *sock, struct msghdr *msg, size_t size, int flags);

/**
 * Find the flow_id for a sock
 * return: true in case of success, false otherwise
 */
static __inline bool
sock_to_flow_id(const struct sock* sock, struct flow_id* flow_id) {
    if(sock->sk_family != AF_INET) {
        flow_id->src_ip = 0;
        flow_id->dest_ip = 0;
        flow_id->src_port = 0;
        flow_id->dest_port = 0;
        flow_id->protocol = 0;
        return false;
    }
    flow_id->src_ip = sock->sk_addrpair >> 32;
    flow_id->dest_ip = sock->sk_daddr;
    flow_id->src_port = cpu_to_be16(sock->sk_portpair >> 16);
    flow_id->dest_port = sock->sk_dport; //already big endian
    flow_id->protocol = sock->sk_protocol;
    return true;
}

/**
 * Find the flow_id for a server sock
 * return: true in case of success, false otherwise
 */
static __inline bool
server_sock_to_flow_id(const struct sock* sock, struct flow_id* flow_id) {
    if(sock->sk_family != AF_INET) {
        flow_id->src_ip = 0;
        flow_id->dest_ip = 0;
        flow_id->src_port = 0;
        flow_id->dest_port = 0;
        flow_id->protocol = 0;
        return false;
    }
    flow_id->src_ip = sock->sk_daddr;
    flow_id->dest_ip = sock->sk_addrpair >> 32;
    flow_id->src_port = sock->sk_dport; //already big endian
    flow_id->dest_port = cpu_to_be16(sock->sk_portpair >> 16);
    flow_id->protocol = sock->sk_protocol;
    return true;
}

#endif

/**
 * Compare 2 struct flow_id
 * return: true if the flow_ids are equal
 */
static __inline bool
flow_id_equal(const struct flow_id* flow_a, const struct flow_id* flow_b) {
    //return memcmp(flow_a, flow_b, sizeof(struct flow_id)) == 0;
    return flow_a->src_ip == flow_b->src_ip && flow_a->dest_ip == flow_b->dest_ip &&
           flow_a->src_port == flow_b->src_port && flow_a->dest_port == flow_b->dest_port &&
           flow_a->protocol == flow_b->protocol;
}

/**
 * Initialization function for a struct flow_iter*.
 * flow: the flow for which the iter has to be initialized.
 * return: pointer to the first byte of the flow.
 */
static __inline byte*
iter_init(struct flow_iter* iter, struct flow* flow) {
    iter->current_flow_elem = flow->head;
    iter->index = 0;
    if(_unlikely(!iter->current_flow_elem || !iter->current_flow_elem->len))
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

    while(_unlikely(iter->index >= iter->current_flow_elem->len)) {
        if(!iter->current_flow_elem->next)
            return NULL;
        iter->current_flow_elem = iter->current_flow_elem->next;
        iter->index = 0;
    }
    return (byte*)iter->current_flow_elem->buff + iter->index;
}


#endif
