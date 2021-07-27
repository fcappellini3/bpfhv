#ifndef __EBPF_IDS_H__
#define __EBPF_IDS_H__


#include "ebpf_ids_common.h"
#include "auto_rules.h"


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
 * Deep scan the packet
 * pkt: current struct bpfhv_pkt*. Assumed not to be NULL and to be a valid ip packet.
 */
 static __inline uint32_t
 __ids_deep_scan(struct bpfhv_pkt* pkt) {
     uint32_t alarm_index;
     byte* pkt_payload;
     uint32_t pkt_payload_size;
     struct ids_capture_protocol* cap_prot;
     struct flow_id flow_id;
     struct tcphdr* tcp_header;
     struct udphdr* udp_header;
     struct flow* flow;
     char str[32];

     // Debug
     str[0]='D'; str[1]='e'; str[2]='e'; str[3]='p'; str[4]=' '; str[5]='s'; str[6]='c'; str[7]='a'; str[8]='n'; str[9]=0;
     print_num(str, 0);

     // Get global memory
     struct global* global = get_shared_memory();

     // Find packet payload and flow_id
     struct iphdr* ip_header = get_ip_header(pkt);
     if(ip_header->version != 4) {
         return IDS_PASS;
     }
     flow_id.src_ip = ip_header->saddr;
     flow_id.dest_ip = ip_header->daddr;
     flow_id.protocol = ip_header->protocol;
     switch(ip_header->protocol) {
         case IPPROTO_UDP:
             udp_header = get_udp_header(pkt);
             flow_id.src_port = udp_header->source;
             flow_id.dest_port = udp_header->dest;
             pkt_payload = get_udp_payload(pkt, &pkt_payload_size);
             break;
         case IPPROTO_TCP:
             tcp_header = get_tcp_header(pkt);
             flow_id.src_port = tcp_header->source;
             flow_id.dest_port = tcp_header->dest;
             pkt_payload = get_tcp_payload(pkt, &pkt_payload_size);
             break;
         default:
             return IDS_PASS;
     }
     if(!pkt_payload)
        return IDS_INVALID_PKT;

     // Check if a flow already exists. If it exists we don't have to check for a matching payload,
     // but if there is no flow, we have to search for a matching payload (and maybe start a new
     // flow in case we found one).
     flow = get_flow(&flow_id);
     if(flow) {
         str[0]='a'; str[1]=' '; str[2]='f'; str[3]='l'; str[4]='o'; str[5]='w'; str[6]=' '; str[7]='e'; str[8]='x'; str[9]='i'; str[10]='s'; str[11]='t'; str[12]='s'; str[13]='\n'; str[14]=0;
         print_num(str, 0);
         goto a_flow_exists;
     } else {
         // Scan: search for an "alarm payload" inside pkt_payload
         for(alarm_index = 0; alarm_index < global->alarm_count; ++alarm_index) {
             struct ids_alarm* alarm = &global->alarms[alarm_index];
             uint32_t find_res = find(
                 pkt_payload, pkt_payload_size,
                 alarm->payload, alarm->payload_size
             );
             if(find_res != 0xFFFFFFFFU) {
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
                 flow = create_flow(&flow_id, false, 1*1024*1024);
                 flow->reserved = cap_prot;
                 str[0]='F'; str[1]='l'; str[2]='o'; str[3]='w'; str[4]=' '; str[5]='c'; str[6]='r'; str[7]='e'; str[8]='a'; str[9]='t'; str[10]='e'; str[11]='d'; str[12]=0;
                 print_num(str, 0);
                 if(!flow) {
                     return IDS_LEVEL(10);
                 }
                 goto a_flow_exists;
             }
         }

         // If no payloads were found and no flows were found, this packet is legit
         //if(alarm_index >= global->alarm_count)
         return IDS_PASS;
     }

     a_flow_exists:
     // If I'm here a flow exists (because it was just created or because it was already existing).
     // I have to add the current packet to the flow.
     store_pkt(flow, pkt_payload, pkt_payload_size, false);
     // Check the flow
     cap_prot = (struct ids_capture_protocol*)flow->reserved;
     if(__check_flow(flow, cap_prot)) {
         return IDS_LEVEL(cap_prot->ids_level);
     }
     return IDS_PASS;
 }

/**
 * Apply IDS IP rules. This function must be called by ids_analyze_eth_pkt only
 * pkt: current struct bpfhv_pkt*. Assumed not to be NULL.
 */
static __inline uint32_t
__ids_analyze_ip_pkt(struct bpfhv_pkt* pkt) {
    if(invalid_ip_pkt(pkt))
        return IDS_INVALID_PKT;

    struct iphdr* ip_header = get_ip_header(pkt);
    if(ip_header->version != 4) {
        return IDS_PASS;
    }

    switch(ip_header->protocol) {
        case IPPROTO_UDP:
            return __auto_rules_tcp(pkt);
        case IPPROTO_TCP:
            return __auto_rules_udp(pkt);
        /*case IPPROTO_ICMP:
            return IDS_PASS;*/
        default:
            return IDS_PASS;
    }
}

/**
 * Apply IDS ARP rules. This function must be called by ids_analyze_eth_pkt only.
 * pkt: current struct bpfhv_pkt*. Assumed not to be NULL.
 */
static __inline uint32_t
__ids_analyze_arp_pkt(struct bpfhv_pkt* pkt) {
#if 0
    if(invalid_arp_pkt(pkt_sz))
        return IDS_INVALID_PKT;
    struct arphdr* arp_header = get_arp_header(pkt);
    if(arp_header->ar_hln != 6 && arp_header->ar_pln != 4)
        return IDS_INVALID_PKT;
#endif
#if 0
    // Example of APR poisoning detection
    struct arpethbody* arp_body = get_arp_body(pkt);
    if(
        arp_body->ar_sip == GATEWAY_IP &&
        !mac_equal(arp_body->ar_sha, GATEWAY_MAC)
    )
        return IDS_LEVEL(10);
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
 * pkt: current struct bpfhv_pkt*. Assumed not to be NULL.
 * return: IDS analyzis resulting level
 */
static __inline uint32_t
ids_analyze_eth_pkt(struct bpfhv_pkt* pkt) {
    // Check if the packet is valid before everything else
    if(invalid_eth_pkt(pkt)) {
        return IDS_INVALID_PKT;
    }

    // L2 rules
    uint32_t l2_check = __ids_l2_rules(pkt);
    if(l2_check != IDS_PASS)
        return l2_check;

    // The next step depends on the L3 protocol written in the L2 header
    struct ethhdr* eth_header = get_eth_header(pkt);
    uint16_t proto = be16_to_cpu(eth_header->h_proto);
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
            result = IDS_INVALID_PKT;
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
 * Call ids_analyze_eth_pkt(...) based on current bpfhv_rx_context
 * return: IDS analyzis resulting level
 */
static __inline uint32_t
ids_analyze_eth_pkt_by_context(struct bpfhv_rx_context* ctx) {
    uint32_t level;

    struct bpfhv_pkt* pkt = get_bpfhv_pkt(ctx);
    if(!pkt)
        return IDS_PASS;

    level = ids_analyze_eth_pkt(pkt);

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


#endif
