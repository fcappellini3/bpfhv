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
            .action = DROP
        }
    },
    .cap_protos = {
        {
            .payload = {'/', 'b', 'a', 'd', '_', 'e', 'p'},
            .action = DROP_FLOW
        }
    }
};


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

     // Get global memory
     struct global* global = get_shared_memory();

     // Find packet payload
     struct iphdr* ip_header = get_ip_header(pkt);
     if(ip_header->version != 4) {
         return IDS_PASS;
     }
     switch(ip_header->protocol) {
         case IPPROTO_UDP:
             pkt_payload = get_udp_payload(pkt, &pkt_payload_size);
             break;
         case IPPROTO_TCP:
             pkt_payload = get_tcp_payload(pkt, &pkt_payload_size);
             break;
         case IPPROTO_ICMP:
             return IDS_PASS;
         default:
             return IDS_INVALID_PKT;
     }
     if(!pkt_payload)
        return IDS_INVALID_PKT;

     // Scan: search for an "alarm payload" inside pkt_payload
     for(alarm_index = 0; alarm_index < global->alarm_count; ++alarm_index) {
         struct ids_alarm* alarm = &global->alarms[alarm_index];
         uint32_t find_res = find(
             pkt_payload, pkt_payload_size,
             alarm->payload, alarm->payload_size
         );
         if(find_res != 0xFFFFFFFFU) {
             // The current pkt match an alarm
             char s[32]; s[0] = 'f'; s[1] = 'o'; s[2] = 'u'; s[3] = 'n'; s[4] = 'd'; s[5] = ' ';
             s[6] = 'a'; s[7] = 't'; s[8] = 0;
             print_num(s, find_res);

             bpf_memcpy(s, alarm->payload, alarm->payload_size);
             s[alarm->payload_size] = 0;
             print_num(s, alarm_index);

             /*bpf_memcpy(s, pkt_payload + find_res, alarm->payload_size);
             print_num(s, alarm_index);*/

             bpf_memcpy(s, pkt_payload, 20);
             s[20] = 0;
             print_num(s, 0);

             if(alarm->action == CAPTURE) {
                 cap_prot = &global->cap_protos[alarm->cap_prot_index];
             } else {  //alarm->action == DROP
                 return IDS_LEVEL(10);
             }
         }
     }

     // Apply cap_prot
     return IDS_PASS;  // TODO
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
        case IPPROTO_ICMP:
            return IDS_PASS;
        default:
            return IDS_INVALID_PKT;
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
