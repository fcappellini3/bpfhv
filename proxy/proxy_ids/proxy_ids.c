/**
 * This module provide an "equivalent" version of the EBPF IDS that can be compiled in userspace
 * with the proxy backend program and must be used for test pourposes only
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "proxy_ids.h"
#include "bpfhv_pkt.h"
#include "net_headers.h"


#ifndef likely
#define likely(x)           __builtin_expect((x), 1)
#endif
#ifndef unlikely
#define unlikely(x)         __builtin_expect((x), 0)
#endif


/*
 * ================================================
 * = Flow data structures rearranged to work here =
 * ================================================
 */

#define DEFAULT_FLOW_SIZE 1*1024*1024
#define STORE_PKT_SUCCESS  0
#define STORE_PKT_ERROR    1
#define STORE_PKT_REJECTED 2

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
    struct flow_id flow_id;
    void* reserved_bpf;
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

enum ids_alarm_action {
    DROP,
    CAPTURE
};

enum ids_capture_protocol_action {
    DROP_FLOW
};

struct ids_alarm {
    uint32_t cap_prot_index;
    uint32_t payload_size;
    enum ids_alarm_action action;
    byte payload[MAX_IDS_ALARM_PAYLOAD_SIZE];
};

struct ids_capture_protocol {
    enum ids_capture_protocol_action action;
    uint32_t payload_size;
    uint32_t ids_level;
    byte payload[MAX_IDS_CAP_PROT_PAYLOAD_SIZE];
};

/*
 * ================================================
 * = End                                          =
 * ================================================
 */






// bpfhv_pkt
static struct bpfhv_pkt global_bpfhv_pkt;

// IDS rules
struct ids_rules {
    uint32_t alarm_count;
    struct ids_alarm alarms[1];
    struct ids_capture_protocol cap_protos[1];
};

struct ids_rules ids_rules = {
    .alarm_count = 1,
    .alarms = {
        {
            .cap_prot_index = 0,
            .payload_size = 5,
            .payload = {'H', 'T', 'T', 'P', '/'},
            .action = CAPTURE
        }
    },
    .cap_protos = {
        {
            .payload_size = 7,
            .ids_level = 9,
            .payload = {'/', 'b', 'a', 'd', '_', 'e', 'p'},
            .action = DROP_FLOW
        }
    }
};

// Flow hashmap
#define h_key_t struct flow_id
#define h_value_t struct flow*
#include "hashmap.h"
#define HASH_TABLE_SIZE 16
static uint32_t
hash(const h_key_t* flow_id) {
    return (uint32_t)(
        flow_id->src_ip ^ flow_id->dest_ip ^
        ((((uint32_t)flow_id->src_port) << 16) ^ (uint32_t)flow_id->dest_port) ^
        (uint32_t)flow_id->protocol
    ) % HASH_TABLE_SIZE;
}
static inline bool flow_id_equal(const struct flow_id* flow_id_a, const struct flow_id* flow_id_b);
bool hashmap_is_initialized = false;
static struct hashmap flow_hashmap = HASHMAP(HASH_TABLE_SIZE, hash, flow_id_equal);


/**
 * Given an ip header, return the IP payload (that can be an UDP or TCP header)
 * return: IP payload
 */
 static inline byte*
 get_ip_payload(const struct iphdr* ip_header, const uint32_t residual_pkt_len) {
     uint32_t jump = (ip_header->ihl << 2);
     if(jump > residual_pkt_len) {
         return 0;
     }
     return ((byte*)ip_header) + jump;
 }

/**
 * Given a TCP header, return the payload
 * return payload
 */
static inline byte*
get_tcp_payload(const struct tcphdr* tcp_header) {
    uint32_t jump = (tcp_header->doff << 2);
    return (byte*)tcp_header + jump;
}

/**
 * Given a UDP header, return the payload
 * return payload
 */
static inline byte*
get_udp_payload(const struct udphdr* udp_header) {
    return (byte*)udp_header + sizeof(struct udphdr);
}

/**
 * Create a struct bpfhv_pkt* starting from the pointer to its buffer and its length.
 */
static struct bpfhv_pkt*
craft_bpfhv_pkt(void* buff, uint32_t len) {
    global_bpfhv_pkt.raw_buff = buff;  //l2_header and eth_header
    global_bpfhv_pkt.len = len;

    if(unlikely(global_bpfhv_pkt.len < sizeof(struct ethhdr))) {
        fprintf(stderr, "craft_bpfhv_pkt(...) -> invalid global_bpfhv_pkt.len\n");
        return 0;
    }

    switch(be16_to_cpu(global_bpfhv_pkt.eth_header->h_proto)) {
        case ETH_P_IP:
            // Set IP header address
			global_bpfhv_pkt.ip_header = (struct iphdr*)(global_bpfhv_pkt.raw_buff + sizeof(struct ethhdr));
			if(unlikely(global_bpfhv_pkt.ip_header->version != 4)) {
				fprintf(
                    stderr,
                    "craft_bpfhv_pkt(...) -> global_bpfhv_pkt.ip_header->version: %d\n",
                    global_bpfhv_pkt.ip_header->version
                );
				return 0;
			}

            // Set TCP/UDP header address
            global_bpfhv_pkt.l4_header = get_ip_payload(
                global_bpfhv_pkt.ip_header, global_bpfhv_pkt.len - sizeof(struct ethhdr)
            );
            if(unlikely(!global_bpfhv_pkt.l4_header))
                return 0;

            // Set payload address
			switch (global_bpfhv_pkt.ip_header->protocol) {
				case IPPROTO_UDP:
		            global_bpfhv_pkt.payload = get_udp_payload(global_bpfhv_pkt.udp_header);
					break;
		        case IPPROTO_TCP:
		            global_bpfhv_pkt.payload = get_tcp_payload(global_bpfhv_pkt.tcp_header);
					break;
		        case IPPROTO_ICMP:
		            return 0;
		        default:
					fprintf(stderr, "craft_bpfhv_pkt(...) -> invalid global_bpfhv_pkt.ip_header->protocol\n");
		            return 0;
			}
			global_bpfhv_pkt.payload_len = global_bpfhv_pkt.len - ((uintptr_t)global_bpfhv_pkt.payload - (uintptr_t)global_bpfhv_pkt.raw_buff);
            break;
        case ETH_P_IPV6:
            return 0;
		case ETH_P_ARP:
            if(unlikely(
				global_bpfhv_pkt.len < sizeof(struct ethhdr) +
				sizeof(struct arphdr) + sizeof(struct arpethbody)
			)) {
				return 0;
			}
			global_bpfhv_pkt.arp_header = (struct arphdr*)(global_bpfhv_pkt.raw_buff + sizeof(struct ethhdr));
			global_bpfhv_pkt.arp_body = (struct arpethbody*)(
				(uintptr_t)global_bpfhv_pkt.arp_header + sizeof(struct arphdr)
			);
			global_bpfhv_pkt.payload = 0;
			global_bpfhv_pkt.payload_len = 0;
			break;
        default:
            return 0;
    }

    return &global_bpfhv_pkt;
}





/*
 * ================================================
 * = Flow functions rearranged to work here       =
 * ================================================
 */

char to_str_buff[512];

static inline char*
flow_id_to_string(const struct flow_id* flow_id) {
    uint16_t s_port = be16_to_cpu(flow_id->src_port);
    uint16_t d_port = be16_to_cpu(flow_id->dest_port);
    sprintf(
        to_str_buff,
        "flow_id -> src_ip: %d.%d.%d.%d, dest_ip: %d.%d.%d.%d, src_port: %d, dest_port: %d, protocol: %d",
        flow_id->src_ip & 0xFF, (flow_id->src_ip >> 8) & 0xFF, (flow_id->src_ip >> 16) & 0xFF, (flow_id->src_ip >> 24),
        flow_id->dest_ip & 0xFF, (flow_id->dest_ip >> 8) & 0xFF, (flow_id->dest_ip >> 16) & 0xFF, (flow_id->dest_ip >> 24),
        s_port, d_port, flow_id->protocol
    );
    return to_str_buff;
}

/**
 * Get a flow by its flow_id
 */
static inline struct flow*
get_flow(const struct flow_id* flow_id) {
    return (struct flow*)h_get(&flow_hashmap, *flow_id);
}

/**
 * Allocate memory for a new struct flow, then initialize it.
 */
static inline struct flow*
__alloc_flow(const struct flow_id* flow_id, const bool recording_enabled, const uint32_t max_size) {
    struct flow* flow = malloc(sizeof(struct flow));
    if(unlikely(!flow)) {
        return 0;
    }
    bzero(flow, sizeof(*flow));
    flow->flow_id = *flow_id;
    flow->max_size = max_size;
    flow->recording_enabled = recording_enabled;
    return flow;
}

/**
 * Create a new flow
 */
static struct flow*
create_flow(const struct flow_id* flow_id, const bool recording_enabled, const uint32_t max_size) {
    struct flow* flow = __alloc_flow(flow_id, recording_enabled, max_size);
    if(unlikely(!flow)) {
        return 0;
    }
    h_store(&flow_hashmap, *flow_id, flow);
    fprintf(stderr, "Created flow -> %s\n", flow_id_to_string(flow_id));
    return flow;
}

/**
 * Terminate a flow_elem and deallocate memory
 */
static inline void
__free_flow_elem(struct flow_elem* flow_elem) {
    // Check if flow_elem is NULL
    if(unlikely(!flow_elem)) {
        fprintf(stderr, "__free_flow_elem(...) -> called, but flow_elem is NULL\n");
        return;
    }

    // Free memory
    if(flow_elem->buff)
        free(flow_elem->buff);
    free(flow_elem);
}

/**
 * Terminate a flow and deallocate memory
 */
static inline void
__free_flow(struct flow* flow) {
    struct flow_elem* flow_elem;

    // Check if flow_elem is NULL
    if(unlikely(!flow)) {
        fprintf(stderr, "__free_flow(...) -> called, but flow is NULL\n");
        return;
    }

    // Free every flow_elem
    flow_elem = flow->head;
    while(flow_elem) {
        struct flow_elem* next_flow_elem = flow_elem->next;
        __free_flow_elem(flow_elem);
        flow_elem = next_flow_elem;
    }

    // Free the flow itself
    free(flow);
}

/**
 * Delete a flow and free memory
 */
static inline bool
delete_flow(struct flow_id* flow_id) {
    bool ret;
    struct flow* flow = get_flow(flow_id);
    if(!flow) {
        return false;
    }
    ret = h_delete(&flow_hashmap, *flow_id);
    __free_flow(flow);
    fprintf(stderr, "Deleted flow -> %s\n", flow_id_to_string(flow_id));
    return ret;
}

/**
 * Allocate memory for a new struct flow_elem, then initialize it.
 */
static inline struct flow_elem*
__alloc_flow_elem(void* buff, const uint32_t len) {
    struct flow_elem* flow_elem = malloc(sizeof(struct flow_elem));
    if(unlikely(!flow_elem)) {
        fprintf(stderr, "__alloc_flow_elem(...) -> out of memory!");
        return NULL;
    }
    flow_elem->next = NULL;
    flow_elem->len = len;
    flow_elem->buff = malloc(len);
    if(unlikely(!flow_elem->buff)) {
        fprintf(stderr, "__alloc_flow_elem(...) -> out of memory!");
        free(flow_elem);
        return NULL;
    }
    memcpy(flow_elem->buff, buff, len);
    return flow_elem;
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
 * Store a struct flow_elem (a packet) into a flow.
 * flow: the flow in which the packet has to be stored.
 * buff: packet data (you may want to store only the payload)
 * len: packet len (related to data)
 * return: STORE_PKT_SUCCESS, STORE_PKT_ERROR or STORE_PKT_REJECTED
 */
static uint32_t
store_pkt(struct flow* flow, void* buff, const uint32_t len) {
    struct flow_elem* new_flow_elem;

    // If the flow is NULL raise an error
    if(unlikely(!flow)) {
        fprintf(stderr, "store_pkt(...) -> flow is NULL\n");
        return STORE_PKT_ERROR;
    }

    // Check if len is too much for this flow
    if(unlikely(len > flow->max_size)) {
        fprintf(stderr, "store_pkt(...) -> len is too big\n");
        return STORE_PKT_ERROR;
    }

    // Create the new struct flow_elem
    new_flow_elem = __alloc_flow_elem(buff, len);
    if(unlikely(!new_flow_elem))
        return STORE_PKT_ERROR;

    // If the flow is empty store the packet as head/tail
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

    return STORE_PKT_SUCCESS;
}

/**
* Compare 2 struct flow_id
* return: true if the flow_ids are equal
*/
static inline bool
flow_id_equal(const struct flow_id* flow_a, const struct flow_id* flow_b) {
   return flow_a->src_ip == flow_b->src_ip && flow_a->dest_ip == flow_b->dest_ip &&
          flow_a->src_port == flow_b->src_port && flow_a->dest_port == flow_b->dest_port &&
          flow_a->protocol == flow_b->protocol;
}

/**
* Initialization function for a struct flow_iter*.
* flow: the flow for which the iter has to be initialized.
* return: pointer to the first byte of the flow.
*/
static inline byte*
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
static inline byte*
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

/*
* ================================================
* = End                                          =
* ================================================
*/






/*
 * ================================================
 * = Packet analyzis                              =
 * ================================================
 */

/**
* Find "what" inside "where"
* return: index of "what" inside "where" or 0xFFFFFFFFU if not found
*/
static inline uint32_t
find(const byte* where, const uint32_t where_size, const byte* what, const uint32_t what_size) {
    uint32_t i, j, stop;
    bool found;
    if(what_size > where_size)
        return 0xFFFFFFFFU;
    stop = where_size - what_size;
    for(i = 0; i < stop; ++i) {
        found = true;
        for(j = 0; j < what_size; ++j) {
            if(where[i+j] != what[j]) {
                found = false;
                break;
            }
        }
        if(found) {
            return i;
        }
    }
    return 0xFFFFFFFFU;
}

 /**
  * Check a flow w.r.t. a struct ids_capture_protocol.
  * return: true if flow match the condition of cap_prot, false otherwise.
  */
 static inline bool
 __check_flow(struct flow* flow, struct ids_capture_protocol* cap_prot) {
     struct flow_iter iter;
     struct flow_iter iter_copy;
     byte* ptr;
     uint32_t i;

     for(ptr = iter_init(&iter, flow); ptr; ptr = iter_next(&iter)) {
         iter_copy = iter;
         for(i = 0; ptr && i < cap_prot->payload_size; ptr = iter_next(&iter_copy), ++i) {
             if(*ptr != cap_prot->payload[i]) {
                 break;
             }
         }
         if(i == cap_prot->payload_size && ptr) {
             return true;
         }
     }

     return false;
 }


/**
 * Deep scan the packet
 * pkt: current struct bpfhv_pkt*. Assumed not to be NULL and to be a valid ip packet.
 */
static inline uint32_t
__ids_deep_scan(struct bpfhv_pkt* pkt) {
    uint32_t alarm_index;
    uint32_t ret;
    struct ids_capture_protocol* cap_prot;
    struct flow_id flow_id;
    struct tcphdr* tcp_header;
    struct udphdr* udp_header;
    struct flow* flow;

    // Find packet payload and flow_id
    struct iphdr* ip_header = pkt->ip_header;
    if(ip_header->version != 4) {
     return IDS_PASS;
    }
    flow_id.src_ip = ip_header->saddr;
    flow_id.dest_ip = ip_header->daddr;
    flow_id.protocol = ip_header->protocol;
    switch(ip_header->protocol) {
        case IPPROTO_UDP:
            udp_header = pkt->udp_header;
            flow_id.src_port = udp_header->source;
            flow_id.dest_port = udp_header->dest;
            break;
        case IPPROTO_TCP:
            tcp_header = pkt->tcp_header;
            flow_id.src_port = tcp_header->source;
            flow_id.dest_port = tcp_header->dest;
            break;
        default:
            return IDS_PASS;
    }
    if(!pkt->payload) {
        return IDS_INVALID_PKT(4);
    }

    // Check if a flow already exists. If it exists we don't have to check for a matching payload,
    // but if there is no flow, we have to search for a matching payload (and maybe start a new
    // flow in case we found one).
    flow = get_flow(&flow_id);
    if(flow) {
        goto a_flow_exists;
    } else {
        // Scan: search for an "alarm payload" inside pkt->payload
        for(alarm_index = 0; alarm_index < ids_rules.alarm_count; ++alarm_index) {
            struct ids_alarm* alarm = &ids_rules.alarms[alarm_index];
            uint32_t find_res = find(
                pkt->payload, pkt->payload_len,
                alarm->payload, alarm->payload_size
            );
            if(find_res != 0xFFFFFFFFU) {
                // The current pkt matched an alarm
                // If alarm->action is DROP, the packet must be immediatel dropped!
                if(alarm->action == DROP) {
                    return IDS_LEVEL(10);
                }

                // Otherwise, let's chek for the capture protocol and procede to create a new flow
                cap_prot = &ids_rules.cap_protos[alarm->cap_prot_index];
                flow = create_flow(&flow_id, true, DEFAULT_FLOW_SIZE);
                if(!flow) {
                    return IDS_LEVEL(10);
                }
                flow->reserved_bpf = cap_prot;
                goto a_flow_exists;
            }
        }

        // If no payloads were found and no flows were found, this packet is legit
        return IDS_PASS;
    }

    a_flow_exists:
    // If I'm here a flow exists (because it was just created or because it was already existing).
    // If the packet len is greater than 0 the packet must be stored.
    if(pkt->payload_len) {
        store_pkt(flow, pkt->payload, pkt->payload_len);
    }

    // The flow has to be cheked now
    cap_prot = (struct ids_capture_protocol*)flow->reserved_bpf;
    if(__check_flow(flow, cap_prot)) {
        ret = IDS_LEVEL(cap_prot->ids_level);
    } else {
        ret = IDS_PASS;
    }

    // If the protocol is TCP and we have a TCP FIN, the current flow must be terminated and
    // deallocated to free memory.
    if(flow->flow_id.protocol == IPPROTO_TCP && pkt->tcp_header->fin) {
        delete_flow(&flow->flow_id);
    }

    return ret;
  }

static inline uint32_t
__auto_rules_tcp(struct bpfhv_pkt* pkt) {
	struct iphdr* ip_header = pkt->ip_header;
	struct tcphdr* tcp_header = pkt->tcp_header;
  	if(ip_header->saddr == IPADDR_BE(10,0,0,10) && be16_to_cpu(tcp_header->dest) == 9898) {
  		return IDS_LEVEL(6);
  	}
  	return IDS_PASS;
}


static inline uint32_t
__auto_rules_udp(struct bpfhv_pkt* pkt) {
  	struct iphdr* ip_header = pkt->ip_header;
  	struct udphdr* udp_header = pkt->udp_header;
  	if(be16_to_cpu(udp_header->dest) == 9898 && ip_header->saddr == IPADDR_BE(10,0,0,10)) {
  		return IDS_LEVEL(6);
  	}
  	return IDS_PASS;
}

 /**
  * Apply IDS IP rules. This function must be called by ids_analyze_eth_pkt only.
  * This function assumes that pkt is a valid ETH IP packet.
  * pkt: current struct bpfhv_pkt*. Assumed not to be NULL.
  */
 static inline uint32_t
 __ids_analyze_ip_pkt(struct bpfhv_pkt* pkt) {
     struct iphdr* ip_header = pkt->ip_header;
     if(ip_header->version != 4) {
         return IDS_PASS;
     }

     switch(ip_header->protocol) {
         case IPPROTO_UDP:
             return __auto_rules_tcp(pkt);
         case IPPROTO_TCP:
             return __auto_rules_udp(pkt);
         case IPPROTO_ICMP:
             return IDS_PASS;
         default:
             return IDS_PASS;
     }
 }

 /**
  * Apply IDS ARP rules. This function must be called by ids_analyze_eth_pkt only.
  * This function assumes that pkt is a valid APR (ETH) packet.
  * pkt: current struct bpfhv_pkt*. Assumed not to be NULL.
  */
 static inline uint32_t
 __ids_analyze_arp_pkt(struct bpfhv_pkt* pkt) {
 #if 0
     struct arphdr* arp_header = pkt->arp_header;
     if(arp_header->ar_hln != 6 && arp_header->ar_pln != 4) {
         return IDS_INVALID_PKT(2);
     }
 #endif
 #if 0
     // Example of APR poisoning detection
     struct arpethbody* arp_body = pkt->arp_body;
     if(!arp_body) {
         return IDS_INVALID_PKT(3);
     }
     if(
         arp_body->ar_sip == GATEWAY_IP &&
         !mac_equal(arp_body->ar_sha, GATEWAY_MAC)
     ) {
         return IDS_LEVEL(10);
     }
 #endif
     return IDS_PASS;
 }

 /**
  * Apply IDS L2 rules. This function must be called by ids_analyze_eth_pkt only
  * pkt: current struct bpfhv_pkt*. Assumed not to be NULL.
  */
 static inline uint32_t
 __ids_l2_rules(struct bpfhv_pkt* pkt) {
     return IDS_PASS;
 }

/**
 * Analyze an L2 (ETH) packet provided as a struct bpfhv_pkt.
 * This function assumes that pkt is a valid eth packet and does not perform checks.
 * pkt: current struct bpfhv_pkt*. Assumed not to be NULL.
 * return: IDS analyzis resulting level
 */
static inline uint32_t
ids_analyze_eth_pkt(struct bpfhv_pkt* pkt) {
    // L2 rules
    uint32_t l2_check = __ids_l2_rules(pkt);
    if(l2_check != IDS_PASS)
        return l2_check;

    // The next step depends on the L3 protocol written in the L2 header
    uint16_t proto = be16_to_cpu(pkt->eth_header->h_proto);
    uint32_t result;
    switch(proto) {
        case ETH_P_ARP:
            result = __ids_analyze_arp_pkt(pkt);
            break;
        case ETH_P_IP:
            result = __ids_analyze_ip_pkt(pkt);
            break;
        case ETH_P_IPV6:
            return IDS_PASS;
        default:
            result = IDS_INVALID_PKT(1);
            break;
    }

    // If result is not IDS_PASS, the result must be returned immediately before everything else
    // in order to drop the packet
    if(result != IDS_PASS)
        return result;

    // In case the previous analyzes returned IDS_PASS and the current packet is an IP packet, it
    // has to be object of a deep scan
    if(proto == ETH_P_IP)
        result = __ids_deep_scan(pkt);

    return result;
}

/**
 * Docstring in proxy_ids.h
 */
uint32_t
ids_analyze_eth_pkt_by_buffer(void* buff, uint32_t len) {
    uint32_t level;
    struct bpfhv_pkt* bpfhv_pkt;

    // Initialize flow_hashmap if needed
    if(unlikely(!hashmap_is_initialized)) {
        hashmap_ini(&flow_hashmap);
        hashmap_is_initialized = true;
    }

    // Craft a bpfhv_pkt and start analyzis
    bpfhv_pkt = craft_bpfhv_pkt(buff, len);
    if(!bpfhv_pkt) {
        return IDS_PASS;
    }
    level = ids_analyze_eth_pkt(bpfhv_pkt);

    // Print some info
    if(level != IDS_PASS) {
        fprintf(stderr, "level: %d\n", level);
    }

    return level;
}

/*
 * ================================================
 * = End =
 * ================================================
 */


void
proxy_ids_fini(void) {
    hashmap_fini(&flow_hashmap);
}
