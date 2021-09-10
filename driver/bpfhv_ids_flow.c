#include "bpfhv_ids_flow.h"
#include "bpfhv.h"
#include "bpfhv_progs_registry.h"
#include <linux/hashtable.h>  // hashtable API
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uio.h>  // iov_iter
#include <linux/mutex.h>
#include "log.h"


#define HASH_TABLE_BIT_COUNT 4U
#define HASH_TABLE_SIZE (uint32_t)(1U << HASH_TABLE_BIT_COUNT)
#define MIN(A, B) ((A) < (B) ? (A) : (B))


/**
 * Structure that contains data related to the flow that are reserved for the kernelspace
 */
struct flow_kernel_reserved {
    struct mutex flow_mutex;
};

/**
 * Hashtable node
 */
struct h_node {
    struct flow* flow;
    struct hlist_node node;
};


/*
 * Global data
 */
struct mutex flow_hash_table_mutex;
DECLARE_HASHTABLE(flow_hash_table, HASH_TABLE_BIT_COUNT);


/*
 * Function prototypes
 */
bool bpfhv_prog_is_present(struct bpfhv_info* bi, const uint32_t index);
uint32_t run_bpfhv_prog_1(struct bpfhv_info* bi, const uint32_t index, void* arg);
static inline flow_key_t __flow_hash(const struct flow_id* flow_id);


/**
 * Lock a flow's mutex
 */
#define flow_mutex_lock(flow) do{} while(0) //mutex_lock(&flow->reserved_kernel->flow_mutex)

/**
 * Unlock a flow's mutex
 */
#define flow_mutex_unlock(flow) do{} while(0) //mutex_unlock(&flow->reserved_kernel->flow_mutex)

/**
 * HELP/DEBUG functions
 */
#if defined(DEBUG_LEVEL) && DEBUG_LEVEL > 0
char str_buffer[500];

static inline char*
flow_id_to_string(const struct flow_id* flow_id, char* buffer) {
    uint16_t s_port = be16_to_cpu(flow_id->src_port);
    uint16_t d_port = be16_to_cpu(flow_id->dest_port);
    sprintf(
        buffer,
        "flow_id -> src_ip: %d.%d.%d.%d, dest_ip: %d.%d.%d.%d, src_port: %d, dest_port: %d, protocol: %d",
        flow_id->src_ip & 0xFF, (flow_id->src_ip >> 8) & 0xFF, (flow_id->src_ip >> 16) & 0xFF, (flow_id->src_ip >> 24),
        flow_id->dest_ip & 0xFF, (flow_id->dest_ip >> 8) & 0xFF, (flow_id->dest_ip >> 16) & 0xFF, (flow_id->dest_ip >> 24),
        s_port, d_port, flow_id->protocol
    );
    return buffer;
}
#endif

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
__alloc_flow(const struct flow_id* flow_id, const bool recording_enabled, const uint32_t max_size,
             struct bpfhv_info* owner_bpfhv_info) {
    struct flow* flow = kmalloc(sizeof(struct flow), GFP_KERNEL);
    memset(flow, 0, sizeof(*flow));
    flow->owner_bpfhv_info = owner_bpfhv_info;
    flow->reserved_kernel = kmalloc(sizeof(struct flow_kernel_reserved), GFP_KERNEL);
    flow->flow_id = *flow_id;
    flow->max_size = max_size;
    flow->recording_enabled = recording_enabled;
    mutex_init(&flow->reserved_kernel->flow_mutex);
    return flow;
}

/**
 * Allocate memory for a new struct flow_elem, then initialize it.
 */
static struct flow_elem*
__alloc_flow_elem(void* buff, const uint32_t len) {
    struct flow_elem* flow_elem = kmalloc(sizeof(struct flow_elem), GFP_KERNEL);
    if(unlikely(!flow_elem)) {
        printk(KERN_ERR "__alloc_flow_elem(...) -> out of memory!");
        return NULL;
    }
    flow_elem->next = NULL;
    flow_elem->len = len;
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

    // Free kernel reserved data
    kfree(flow->reserved_kernel);

    // Free the flow itself
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
    mutex_init(&flow_hash_table_mutex);
    hash_init(flow_hash_table);
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
}

/**
 * Docstring in ids_flow.h
 */
struct flow*
get_flow(const struct flow_id* flow_id) {
    struct h_node* cur;
    flow_key_t flow_key = __flow_hash(flow_id);

    mutex_lock(&flow_hash_table_mutex);
    hash_for_each_possible(flow_hash_table, cur, node, flow_key) {
        if(flow_id_equal(&cur->flow->flow_id, flow_id)) {
            mutex_unlock(&flow_hash_table_mutex);
            return cur->flow;
        }
    }
    mutex_unlock(&flow_hash_table_mutex);

    return NULL;
}

/**
 * Like get_flow(...), but it does not lock/unlock the flow mutex.
 * It assumes that the mutex was already locked.
 */
 static struct flow*
 get_flow_no_mutex(const struct flow_id* flow_id) {
     struct h_node* cur;
     flow_key_t flow_key = __flow_hash(flow_id);

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
struct flow*
create_flow(
    const struct flow_id* flow_id, const bool recording_enabled, const uint32_t max_size,
    struct bpfhv_info* owner_bpfhv_info
) {
    struct h_node* h_node;
    struct flow* flow;

    // Check if the flow already exists. If yes, raise a warning and return that flow.
    flow = get_flow(flow_id);
    if(unlikely(flow)) {
        printk(KERN_ERR "create_flow(...) -> called, but the flow already exists\n");
        return flow;
    }

    // Create the h_node and the flow
    h_node = kmalloc(sizeof(struct h_node), GFP_KERNEL);
    flow = __alloc_flow(flow_id, recording_enabled, max_size, owner_bpfhv_info);
    if(unlikely(!flow || !h_node)) {
        printk(KERN_ERR "create_flow(...) -> out of memory!\n");
        return NULL;
    }
    h_node->flow = flow;

    // Add the flow to the hash table
    mutex_lock(&flow_hash_table_mutex);
    hash_add(flow_hash_table, &h_node->node, __flow_hash(flow_id));
    mutex_unlock(&flow_hash_table_mutex);

    print_debug("create_flow(...) -> flow created\n");

    // Return the flow
    return flow;
}

/**
 * Docstring in ids_flow.h
 */
bool
delete_flow(struct flow_id* flow_id) {
    struct h_node* cur;
    flow_key_t flow_key = __flow_hash(flow_id);

    mutex_lock(&flow_hash_table_mutex);
    hash_for_each_possible(flow_hash_table, cur, node, flow_key) {
        if(flow_id_equal(&cur->flow->flow_id, flow_id)) {
            print_debug(
                "delete_flow(...) -> deleating -> %s\n", flow_id_to_string(flow_id, str_buffer)
            );
            // Terminate the flow and free memory
            __free_flow(cur->flow);
            // Remove the node from the hash table
            hash_del(&cur->node);
            // Free the h_node
            kfree(cur);
            // Release the mutex and retrun true to signal the correct execution
            mutex_unlock(&flow_hash_table_mutex);
            return true;
        }
    }
    mutex_unlock(&flow_hash_table_mutex);

    print_debug("delete_flow(...) -> failed to delete a flow\n");
    return false;
}

/**
 * Docstring in ids_flow.h
 */
uint32_t
store_pkt(struct flow* flow, void* buff, const uint32_t len) {
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
    new_flow_elem = __alloc_flow_elem(buff, len);
    if(unlikely(!new_flow_elem))
        return STORE_PKT_ERROR;

    // If the flow is empty store the packet as head/tail
    flow_mutex_lock(flow);
    if(flow->elem_count == 0) {
        flow->elem_count = 1;
        flow->size = len;
        flow->head = flow->tail = new_flow_elem;
        return STORE_PKT_SUCCESS;
    }

    // Pop flow head untill there is sufficient room to store new_flow_elem
    while(flow->size + len > flow->max_size) {
        __pop_head_flow(flow);
    }

    // Append new_flow_elem. For how the function is structured, flow->tail is not NULL.
    flow->tail->next = new_flow_elem;
    flow->tail = new_flow_elem;
    ++flow->elem_count;
    flow->size += len;

    // Release mutex
    flow_mutex_unlock(flow);

    return STORE_PKT_SUCCESS;
}

/**
 * Docstring in bpfhv_ids_flow.h
 */
struct bpfhv_info*
get_flow_owner(const struct flow_id* flow_id) {
    struct flow* flow;
    struct bpfhv_info* bpfhv_info = NULL;

    mutex_lock(&flow_hash_table_mutex);
    flow = get_flow_no_mutex(flow_id);
    if(unlikely(flow)) {
        bpfhv_info = flow->owner_bpfhv_info;
    }
    mutex_unlock(&flow_hash_table_mutex);

    return bpfhv_info;
}

/**
 * Docstring in ids_flow.h
 */
int
inet_recvmsg_replacement(struct socket *sock, struct msghdr *msg, size_t size, int flags) {
    struct flow_id flow_id;
    struct flow* flow;
    struct sock *sk = sock->sk;
    unsigned long irq_flags;
    int addr_len = 0;
    int err;

	if(likely(!(flags & MSG_ERRQUEUE)))
	   sock_rps_record_flow(sk);

	err = sk->sk_prot->recvmsg(
        sk, msg, size, flags & MSG_DONTWAIT, flags & ~MSG_DONTWAIT, &addr_len
    );

    if(err < 0) {
        return err;
    }

	msg->msg_namelen = addr_len;

    if(err == 0) {
        return err;
    }

    // If the message is empty, simply return
    if(unlikely(!msg->msg_iter.nr_segs)) {
        return err;
    }

    // Calculate the flow_id related to this socket
    if(!server_sock_to_flow_id(sk, &flow_id)) {
        printk(KERN_ERR "inet_recvmsg_replacement(...) -> sock_to_flow_id(...) failed\n");
        return err;
    }

    // Find the flow that corresponds to this flow_id and check if the recording_enabled flag is
    // enabled. If there is no BPFHV_PROG_SOCKET_READ program, we can avoid further steps.
    local_irq_save(irq_flags);
    mutex_lock(&flow_hash_table_mutex);
    flow = get_flow_no_mutex(&flow_id);
    if(
        !flow || !flow->recording_enabled ||
        !bpfhv_prog_is_present(flow->owner_bpfhv_info, BPFHV_PROG_SOCKET_READ)
    ) {
        mutex_unlock(&flow_hash_table_mutex);
        local_irq_restore(irq_flags);
        return err;
    }

    // Extract data from msghdr, store them and call the appropriete BPF program
    {
        struct srd_handler_arg srd_handler_arg = {
            .flow = flow,
            .buffer_descriptor_array = kmalloc(msg->msg_iter.nr_segs * sizeof(struct buffer_descriptor), GFP_KERNEL),
            .buffer_descriptor_array_size = msg->msg_iter.nr_segs
        };
        uint32_t i;
        uint32_t size;
        uint32_t remaining_size = (uint32_t)err;
        for(i = 0; i < msg->msg_iter.nr_segs && remaining_size; ++i) {
            size = MIN(msg->msg_iter.iov[i].iov_len, remaining_size);
            srd_handler_arg.buffer_descriptor_array[i].buff = msg->msg_iter.iov[i].iov_base;
            srd_handler_arg.buffer_descriptor_array[i].len = size;
            remaining_size -= size;
        }
        run_bpfhv_prog_1(flow->owner_bpfhv_info, BPFHV_PROG_SOCKET_READ, &srd_handler_arg);
        kfree(srd_handler_arg.buffer_descriptor_array);
    }

    // Unlock mutex and restore local IRQ status
    mutex_unlock(&flow_hash_table_mutex);
    local_irq_restore(irq_flags);


    /*printk(KERN_ERR "flow_check_result: %d\n", flow_check_result);
    send_hypervisor_signal(flow->owner_bpfhv_info, 0, flow_check_result);*/

	return err;
}


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Federico Cappellini");
