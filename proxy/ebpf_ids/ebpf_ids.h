#ifndef __EBPF_IDS_H__
#define __EBPF_IDS_H__


#include "ebpf_ids_common.h"
#include "auto_rules.h"


/**
 * Apply IDS IP rules. This function must be called by ids_analyze_eth_pkt only
 * raw_pkt_data: pointer to the raw data of the packet
 * pkt_sz: packet size
*/
static inline uint32_t
__ids_analyze_ip_pkt(uint8_t* raw_pkt_data, uint32_t pkt_sz) {
    if(invalid_ip_pkt(pkt_sz))
        return IDS_INVALID_PKT;

    struct iphdr* ip_header = get_ip_header(raw_pkt_data);
    if(ip_header->version != 4) {
        return IDS_PASS;
    }

    switch(ip_header->protocol) {
        case IPPROTO_UDP:
            return __auto_rules_tcp(raw_pkt_data, pkt_sz);
        case IPPROTO_TCP:
            return __auto_rules_udp(raw_pkt_data, pkt_sz);
        case IPPROTO_ICMP:
            return IDS_PASS;
        default:
            return IDS_INVALID_PKT;
    }
}

/**
 * Apply IDS ARP rules. This function must be called by ids_analyze_eth_pkt only
 * raw_pkt_data: pointer to the raw data of the packet
 * pkt_sz: packet size
*/
static inline uint32_t
__ids_analyze_arp_pkt(uint8_t* raw_pkt_data, uint32_t pkt_sz) {
    return IDS_PASS;
}

/**
 * Apply IDS L2 rules. This function must be called by ids_analyze_eth_pkt only
 * raw_pkt_data: pointer to the raw data of the packet
 * pkt_sz: packet size
*/
static inline uint32_t
__ids_l2_rules(uint8_t* raw_pkt_data, uint32_t pkt_sz) {
    return IDS_PASS;
}

/**
 * Analyze an L2 (ETH) packet
 * raw_pkt_data: pointer to the raw data of the packet
 * pkt_sz: packet size
*/
static inline uint32_t
ids_analyze_eth_pkt(uint8_t* raw_pkt_data, uint32_t pkt_sz) {
    if(!raw_pkt_data)
        return IDS_INVALID_PKT;

    // Check if the packet is valid before everything else
    if(invalid_eth_pkt(pkt_sz)) {
        return IDS_INVALID_PKT;
    }

    // L2 rules
    uint32_t l2_check = __ids_l2_rules(raw_pkt_data, pkt_sz);
    if(l2_check != IDS_PASS)
        return l2_check;

    // The next step depends on the L3 protocol written in the L2 header
    struct ethhdr* eth_header = (struct ethhdr*)raw_pkt_data;
    uint16_t proto = be16_to_cpu(eth_header->h_proto);
    uint32_t result;
    switch(proto) {
        case ETH_P_ARP:
            result = __ids_analyze_arp_pkt(raw_pkt_data, pkt_sz);
            break;
        case ETH_P_IP:
            result = __ids_analyze_ip_pkt(raw_pkt_data, pkt_sz);
            break;
        default:
            result = IDS_INVALID_PKT;
            break;
    }

    // Return
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
static inline uint32_t
sring_ids_analyze_eth_pkt(struct bpfhv_rx_context* ctx) {
    uint32_t level = ids_analyze_eth_pkt(eth_data(ctx), eth_size(ctx));
    if(IS_CRITICAL(level))
        force_close_socket(ctx);
    return level;
}


#endif
