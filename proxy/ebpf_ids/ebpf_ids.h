#ifndef __EBPF_IDS_H__
#define __EBPF_IDS_H__


#include "ebpf_ids_common.h"
#include "auto_rules.h"


__section("pdt")
const char ciao[] = "Ciaooo!";

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

    // Return
    //print_num(get_shared_memory(), 100);
    if(result == IDS_INVALID_PKT) {
        //print_num("Invalid packet", pkt_sz);
    } else if(result != IDS_PASS) {
        char* str = get_shared_memory();
        if(str) {
            str[0] = 'l';
            str[1] = 'e';
            str[2] = 'v';
            str[3] = 'e';
            str[4] = 'l';
            str[5] = 0;
            print_num(str, result);
        }
    }
    return result;
}

/**
 * Call ids_analyze_eth_pkt(...) based on current bpfhv_rx_context
 */
static __inline uint32_t
ids_analyze_eth_pkt_by_context(struct bpfhv_rx_context* ctx) {
    struct bpfhv_pkt* pkt = get_bpfhv_pkt(ctx);
    if(!pkt)
        return IDS_PASS;
    return ids_analyze_eth_pkt(pkt);
}


#endif
