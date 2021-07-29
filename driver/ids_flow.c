#include "ids_flow.h"
#include <linux/hashtable.h> // hashtable API


#define HASH_TABLE_BIT_COUNT 4U
#define HASH_TABLE_SIZE (uint32_t)(1U << HASH_TABLE_BIT_COUNT)


struct h_node {
    struct flow* flow;
    struct hlist_node node;
};


DECLARE_HASHTABLE(flow_hash_table, HASH_TABLE_BIT_COUNT);


/**
 * HELP/DEBUG functions
 */
static void
__print_flow_id(const struct flow_id* flow_id) {
    flow_key_t flow_key = __flow_hash(flow_id);
    uint16_t s_port = be16_to_cpu(flow_id->src_port);
    uint16_t d_port = be16_to_cpu(flow_id->dest_port);
    printk(
        KERN_ERR "flow_id -> src_ip: %d.%d.%d.%d, dest_ip: %d.%d.%d.%d, src_port: %d, dest_port: %d, protocol: %d, flow_key: %d\n",
        flow_id->src_ip & 0xFF, (flow_id->src_ip >> 8) & 0xFF, (flow_id->src_ip >> 16) & 0xFF, (flow_id->src_ip >> 24),
        flow_id->dest_ip & 0xFF, (flow_id->dest_ip >> 8) & 0xFF, (flow_id->dest_ip >> 16) & 0xFF, (flow_id->dest_ip >> 24),
        s_port, d_port, flow_id->protocol, flow_key
    );
}


/**
 * Compute the hash (hashtable key) from a struct flow_id
 */
static inline flow_key_t
__flow_hash(const struct flow_id* flow_id) {
    return (flow_key_t)(
        flow_id->src_ip ^ flow_id->dest_ip ^
        ((((flow_key_t)flow_id->src_port) << 16) ^ (flow_key_t)flow_id->dest_port) ^
        (flow_key_t)flow_id->protocol
    ) % HASH_TABLE_SIZE;
}

/**
 * Allocate memory for a new struct flow, then initialize it.
 */
static struct flow*
__alloc_flow(const struct flow_id* flow_id, const bool ordered, const uint32_t max_size) {
    struct flow* flow = kmalloc(sizeof(struct flow), GFP_KERNEL);
    memset(flow, 0, sizeof(*flow));
    flow->flow_id = *flow_id;
    flow->max_size = max_size;
    flow->ordered = ordered;
    return flow;
}

/**
 * Allocate memory for a new struct flow_elem, then initialize it.
 */
static struct flow_elem*
__alloc_flow_elem(void* buff, const uint32_t len, const uint16_t order) {
    struct flow_elem* flow_elem = kmalloc(sizeof(struct flow_elem), GFP_KERNEL);
    if(unlikely(!flow_elem)) {
        printk(KERN_ERR "__alloc_flow_elem(...) -> out of memory!");
        return NULL;
    }
    flow_elem->next = NULL;
    flow_elem->len = len;
    flow_elem->order = order;
    flow_elem->buff = kmalloc(len, GFP_KERNEL);
    if(unlikely(!flow_elem->buff)) {
        printk(KERN_ERR "__alloc_flow_elem(...) -> out of memory!");
        kfree(flow_elem);
        return NULL;
    }
    memcpy(flow_elem->buff, buff, len);
    return flow_elem;
}

/**
 * Terminate a flow_elem and deallocate memory
 */
static void
__free_flow_elem(struct flow_elem* flow_elem) {
    // Check if flow_elem is NULL
    if(unlikely(!flow_elem)) {
        printk(KERN_ERR "__free_flow_elem(...) -> called, but flow_elem is NULL\n");
        return;
    }

    // Free memory
    if(flow_elem->buff)
        kfree(flow_elem->buff);
    kfree(flow_elem);
}

/**
 * Terminate a flow and deallocate memory
 */
static void
__free_flow(struct flow* flow) {
    struct flow_elem* flow_elem;

    // Check if flow_elem is NULL
    if(unlikely(!flow)) {
        printk(KERN_ERR "__free_flow(...) -> called, but flow is NULL\n");
        return;
    }

    // Free every flow_elem
    flow_elem = flow->head;
    while(flow_elem) {
        struct flow_elem* next_flow_elem = flow_elem->next;
        __free_flow_elem(flow_elem);
        flow_elem = next_flow_elem;
    }
    kfree(flow);
}

/**
 * Remove the head from the flow.
 * flow: the flow. Assumed not to be NULL.
 */
static inline void
__pop_head_flow(struct flow* flow) {
    struct flow_elem* old_head;

    if(unlikely(!flow->elem_count))
        return;

    if(flow->elem_count == 1) {
        flow->elem_count = 0;
        flow->size = 0;
        __free_flow_elem(flow->head);
        flow->head = flow->tail = NULL;
        return;
    }

    old_head = flow->head;
    flow->head = old_head->next;
    --flow->elem_count;
    flow->size -= old_head->len;
    __free_flow_elem(old_head);
}

/**
 * Docstring in ids_flow.h
 */
void
ids_flow_ini(void) {
    hash_init(flow_hash_table);
    printk(KERN_ERR "ids_flow_ini(void) -> Hello!\n");
}

/**
 * Docstring in ids_flow.h
 */
void
ids_flow_fini(void) {
    //Deallocate every entry of the hash table
    struct h_node* cur;
    unsigned bkt;
    hash_for_each(flow_hash_table, bkt, cur, node) {
        __free_flow(cur->flow);
    }
    printk(KERN_ERR "ids_flow_fini(void) -> Bye bye\n");
}

/**
 * Docstring in ids_flow.h
 */
static inline bool
flow_id_equal(const struct flow_id* flow_a, const struct flow_id* flow_b) {
    //return memcmp(flow_a, flow_b, sizeof(struct flow_id)) == 0;
    return flow_a->src_ip == flow_b->src_ip && flow_a->dest_ip == flow_b->dest_ip &&
           flow_a->src_port == flow_b->src_port && flow_a->dest_port == flow_b->dest_port &&
           flow_a->protocol == flow_b->protocol;
}

/**
 * Docstring in ids_flow.h
 */
static struct flow*
get_flow(const struct flow_id* flow_id) {
    struct h_node* cur;
    flow_key_t flow_key = __flow_hash(flow_id);
    //__print_flow_id(flow_id);

    hash_for_each_possible(flow_hash_table, cur, node, flow_key) {
        if(flow_id_equal(&cur->flow->flow_id, flow_id)) {
            return cur->flow;
        }
    }

    return NULL;
}

/**
 * Docstring in ids_flow.h
 */
static struct flow*
create_flow(const struct flow_id* flow_id, const bool ordered, const uint32_t max_size) {
    struct h_node* h_node;

    // Check if the flow already exists. If yes, raise a warning and return that flow.
    struct flow* flow = get_flow(flow_id);
    if(unlikely(flow)) {
        printk(KERN_ERR "create_flow(...) -> called, but the flow already exists\n");
        return flow;
    }

    // Create the h_node and the flow
    h_node = kmalloc(sizeof(struct h_node), GFP_KERNEL);
    flow = __alloc_flow(flow_id, ordered, max_size);
    if(unlikely(!flow || !h_node)) {
        printk(KERN_ERR "create_flow(...) -> out of memory!\n");
        return NULL;
    }
    h_node->flow = flow;

    // Add the flow to the hash table
    hash_add(flow_hash_table, &h_node->node, __flow_hash(flow_id));

    // Return the flow
    return flow;
}

/**
 * Docstring in ids_flow.h
 */
static bool
delete_flow(struct flow_id* flow_id) {
    struct h_node* cur;
    flow_key_t flow_key = __flow_hash(flow_id);

    hash_for_each_possible(flow_hash_table, cur, node, flow_key) {
        if(flow_id_equal(&cur->flow->flow_id, flow_id)) {
            printk(KERN_ERR "delete_flow(...) -> deleating ->");
            __print_flow_id(flow_id);
            // Terminate the flow and free memory
            __free_flow(cur->flow);
            // Remove the node from the hash table
            hash_del(&cur->node);
            // Free the h_node
            kfree(cur);
            // Retrun true to signal the correct execution
            return true;
        }
    }

    printk(KERN_ERR "delete_flow(...) -> called, but the flow does not exist\n");
    return false;
}

/**
 * Docstring in ids_flow.h
 */
static uint32_t
store_pkt(struct flow* flow, void* buff, const uint32_t len, const uint16_t order) {
    struct flow_elem* new_flow_elem;

    // If the flow is NULL raise an error
    if(unlikely(!flow)) {
        printk(KERN_ERR "store_pkt(...) -> flow is NULL\n");
        return STORE_PKT_ERROR;
    }

    // Check if len is too much for this flow
    if(unlikely(len > flow->max_size)) {
        printk(KERN_ERR "store_pkt(...) -> len is too big\n");
        return STORE_PKT_ERROR;
    }

    // Create the new struct flow_elem
    new_flow_elem = __alloc_flow_elem(buff, len, order);
    if(unlikely(!new_flow_elem))
        return STORE_PKT_ERROR;

    // If the flow is empty store the packet as head/tail
    if(flow->elem_count == 0) {
        flow->elem_count = 1;
        flow->size = len;
        flow->head = flow->tail = new_flow_elem;
        return STORE_PKT_SUCCESS;
    }

    // If the flow is not empty and has the ordered flag enabled, we have to check if this packet
    // is in-order
    /*if(flow->ordered && order != NEXT_TCP_ORDER(flow->tail->order)) {
        return STORE_PKT_REJECTED;
    }*/

    // Pop flow head untill there is sufficient room to store new_flow_elem
    while(flow->size + len > flow->max_size) {
        __pop_head_flow(flow);
    }

    // Append new_flow_elem. For how the function is structured, flow->tail is not NULL.
    flow->tail->next = new_flow_elem;
    flow->tail = new_flow_elem;
    ++flow->elem_count;
    flow->size += len;

    return STORE_PKT_SUCCESS;
}
