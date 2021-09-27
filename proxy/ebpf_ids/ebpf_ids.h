#ifndef __EBPF_IDS_H__
#define __EBPF_IDS_H__


#include "ebpf_ids_common.h"
#include "auto_rules.h"

#define DEFAULT_FLOW_SIZE (1*1024*1024)
#define MAX_STORE_SIZE (DEFAULT_FLOW_SIZE / 2)

#define get_reserved_bpf(flow) ((struct reserved_bpf*)((flow)->reserved_bpf))


struct global {
    uint32_t alarm_count;
    struct ids_alarm alarms[1];
    struct ids_capture_protocol cap_protos[1];
};

__section("pdt")
struct global global_ = {
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


/**
 * Debug only: print an error code
 */
static __inline void
print_debug(const uint32_t code) {
    char str[32];
    str[0]='D'; str[1]='e'; str[2]='b'; str[3]='u'; str[4]='g'; str[5]=' '; str[6]='c'; str[7]='o'; str[8]='d'; str[9]='e'; str[10]=0;
    print_num(str, code);
}

/**
 * Check a flow w.r.t. a struct ids_capture_protocol.
 * return: true if flow match the condition of cap_prot, false otherwise.
 */
static __inline bool
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
 * Check a flow w.r.t. its own struct ids_capture_protocol.
 * Send a signal to the hypervisor in case of a match.
 * Reset bytes_stored_from_last_check.
 */
static __inline void
check_flow(struct flow* flow) {
    if(unlikely(__check_flow(flow, get_reserved_bpf(flow)->cap_prot))) {
        char str[32];
        str[0]='F'; str[1]='l'; str[2]='o'; str[3]='w'; str[4]=' '; str[5]='c'; str[6]='h'; str[7]='e'; str[8]='c'; str[9]='k'; str[10]=' '; str[11]='r'; str[12]='e'; str[13]='s'; str[14]='u'; str[15]='l'; str[16]='t'; str[17]=0;
        print_num(str, IDS_LEVEL(get_reserved_bpf(flow)->cap_prot->ids_level));
        send_hypervisor_signal(
            flow->owner_bpfhv_info,
            0,
            IDS_LEVEL(get_reserved_bpf(flow)->cap_prot->ids_level)
        );
    }
    get_reserved_bpf(flow)->bytes_stored_from_last_check = 0;
}


/**
 * Deep scan the packet
 * pkt: current struct bpfhv_pkt*. Assumed not to be NULL and to be a valid ip packet.
 */
 static __inline uint32_t
 __ids_deep_scan(struct bpfhv_rx_context* ctx, struct bpfhv_pkt* pkt) {
     uint32_t alarm_index;
     struct ids_capture_protocol* cap_prot;
     struct flow_id flow_id;
     struct tcphdr* tcp_header;
     struct udphdr* udp_header;
     struct flow* flow;

     // Get global memory
     struct global* global = get_shared_memory();

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
        print_debug(4);
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
         for(alarm_index = 0; alarm_index < global->alarm_count; ++alarm_index) {
             struct ids_alarm* alarm = &global->alarms[alarm_index];
             uint32_t find_res = find(
                 pkt->payload, pkt->payload_len,
                 alarm->payload, alarm->payload_size
             );
             if(unlikely(find_res != NOT_FOUND)) {
                 // The current pkt matched an alarm
                 char s[32]; s[0] = 'f'; s[1] = 'o'; s[2] = 'u'; s[3] = 'n'; s[4] = 'd'; s[5] = ' ';
                 s[6] = 'a'; s[7] = 't'; s[8] = 0;
                 print_num(s, find_res);

                 bpf_memcpy(s, alarm->payload, alarm->payload_size);
                 s[alarm->payload_size] = 0;
                 print_num(s, alarm_index);

                 // If alarm->action is DROP, the packet must be immediatel dropped!
                 if(alarm->action == DROP) {
                     return IDS_LEVEL(10);
                 }

                 // Otherwise, let's chek for the capture protocol and procede to create a new flow
                 cap_prot = &global->cap_protos[alarm->cap_prot_index];
                 flow = create_flow(&flow_id, true, DEFAULT_FLOW_SIZE, ctx);
                 if(!flow) {
                     return IDS_LEVEL(10);
                 }
                 get_reserved_bpf(flow)->cap_prot = cap_prot;
                 get_reserved_bpf(flow)->bytes_stored_from_last_check = 0;
                 goto a_flow_exists;
             }
         }

         // If no payloads were found and no flows were found, this packet is legit
         return IDS_PASS;
     }

     a_flow_exists:
     // If I'm here a flow exists (because it was just created or because it was already existing).
     // Flow checking and deleating are managed later

     return IDS_PASS;
 }

/**
 * Apply IDS IP rules. This function must be called by ids_analyze_eth_pkt only.
 * This function assumes that pkt is a valid ETH IP packet.
 * pkt: current struct bpfhv_pkt*. Assumed not to be NULL.
 */
static __inline uint32_t
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
            print_debug(5);
            return IDS_PASS;
    }
}

/**
 * Apply IDS ARP rules. This function must be called by ids_analyze_eth_pkt only.
 * This function assumes that pkt is a valid APR (ETH) packet.
 * pkt: current struct bpfhv_pkt*. Assumed not to be NULL.
 */
static __inline uint32_t
__ids_analyze_arp_pkt(struct bpfhv_pkt* pkt) {
#if 0
    struct arphdr* arp_header = pkt->arp_header;
    if(arp_header->ar_hln != 6 && arp_header->ar_pln != 4) {
        print_debug(2);
        return IDS_INVALID_PKT(2);
    }
#endif
#if 0
    // Example of APR poisoning detection
    struct arpethbody* arp_body = pkt->arp_body;
    if(!arp_body) {
        print_debug(2);
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
static __inline uint32_t
__ids_l2_rules(struct bpfhv_pkt* pkt) {
    return IDS_PASS;
}

/**
 * Analyze an L2 (ETH) packet provided as a struct bpfhv_pkt.
 * This function assumes that pkt is a valid eth packet and does not perform checks.
 * pkt: current struct bpfhv_pkt*. Assumed not to be NULL.
 * return: IDS analyzis resulting level
 */
static __inline uint32_t
ids_analyze_eth_pkt(struct bpfhv_rx_context* ctx, struct bpfhv_pkt* pkt) {
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
            print_debug(1);
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
        result = __ids_deep_scan(ctx, pkt);

    return result;
}

/**
 * Call ids_analyze_eth_pkt(...) based on current bpfhv_rx_context
 * return: IDS analyzis resulting level
 */
static __inline uint32_t
ids_analyze_eth_pkt_by_context(struct bpfhv_rx_context* ctx) {
    uint32_t level;

    struct bpfhv_pkt* pkt = get_bpfhv_pkt(ctx, 0);
    if(!pkt)
        return IDS_PASS;

    level = ids_analyze_eth_pkt(ctx, pkt);

    // Print some info
    if(level != IDS_PASS) {
        char str[32];
        str[0] = 'l';
        str[1] = 'e';
        str[2] = 'v';
        str[3] = 'e';
        str[4] = 'l';
        str[5] = 0;
        print_num(str, level);
    }

    return level;
}

#ifdef IDS

/**
 * Receive post process handler (rxh)
 * return: BPFHV_PROG_RX_POSTPROC_PKT_DROP to signal that the packet must be dropped or
 *         BPFHV_PROG_RX_POSTPROC_OK to signal that the packet is legit and can be forwarded to
 *         higher levels of the network stack
 */
__section("rxh")
int
rxh_handler(struct bpfhv_rx_context *ctx)
{
    uint32_t level = ids_analyze_eth_pkt_by_context(ctx);
    if(IS_CRITICAL(level))
        return BPFHV_PROG_RX_POSTPROC_PKT_DROP;
    return BPFHV_PROG_RX_POSTPROC_OK;
}

/**
 * This "hadler" is called whenever a socket is released.
 * In this case the only thing we have to do is to delete the corresponding flow.
 * flow_id: flow_id that corresponds to the releasing socket.
 */
__section("srl")
int
socket_released_handler(struct flow_id* flow_id) {
    delete_flow(flow_id);
    return 0;
}

/**
 * This handler is called whenever something reads from a socket that is related to a flow managed
 * by the current instance of BPFHV
 */
__section("srd")
uint32_t
socket_read_handler(struct srd_handler_arg* arg) {
    uint32_t i;
    uint32_t store_result;
    uint32_t stored_size = 0;
    byte* buff;
    uint32_t len;
    uint32_t step_len;

    // Store in the flow everything in arg (max len per store: MAX_STORE_SIZE)
    for(i = 0; i < arg->buffer_descriptor_array_size; ++i) {
        buff = (byte*)arg->buffer_descriptor_array[i].buff;
        len = arg->buffer_descriptor_array[i].len;
        while(len) {
            step_len = MIN(len, MAX_STORE_SIZE);
            store_result = store_pkt(arg->flow, buff, step_len);
            if(unlikely(store_result != STORE_PKT_SUCCESS)) {
                print_debug(6);
                break;
            }
            get_reserved_bpf(arg->flow)->bytes_stored_from_last_check += step_len;
            stored_size += step_len;
            buff += step_len;
            len -= step_len;

            // If enough bytes are stored perform a check
            if(get_reserved_bpf(arg->flow)->bytes_stored_from_last_check >= MAX_STORE_SIZE) {
                check_flow(arg->flow);
            }
        }
    }

    // Perform flow checking at the end independently of bytes_stored_from_last_check
    check_flow(arg->flow);

    return stored_size;
}

#endif

#endif
