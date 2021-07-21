#ifndef __EBPF_IDS_COMMON_H__
#define __EBPF_IDS_COMMON_H__


// Common dependencies
#include "net_headers.h"
#include <stdint.h>
#include "bpf_utils.h"


// Data types
typedef uint8_t bool;


// Helper functions
static struct bpfhv_pkt* BPFHV_FUNC(get_bpfhv_pkt, struct bpfhv_rx_context *ctx);
static int BPFHV_FUNC(print_num, const char* str, long long int x);
static void* BPFHV_FUNC(get_shared_memory);
static uint32_t BPFHV_FUNC(force_close_socket, struct bpfhv_rx_context *ctx);


// Constants
#define IDS_INVALID_PKT 0xFFFFFFFFU
#define IDS_PASS        0x00U


// Macros
#define IPADDR(a1,a2,a3,a4)    (uint32_t)((a1) << 24 | (a2) << 16 | (a3) << 8 | (a4))
#define IPADDR_BE(a1,a2,a3,a4)   (__be32)((a4) << 24 | (a3) << 16 | (a2) << 8 | (a1))
#define IDS_LEVEL(A) (A)
#define IS_CRITICAL(A) ((A) > 5)


/**
 * Given a bpfhv_pkt* pkt, return the ethernet header
 * return: ethernet header
*/
static inline struct ethhdr*
get_eth_header(struct bpfhv_pkt* pkt) {
    return (struct ethhdr*)pkt->raw_buff;
}

/**
 * Given a bpfhv_pkt* pkt, return the payload address
 * return: ethernet payload
*/
static inline uint8_t*
get_eth_payload(struct bpfhv_pkt* pkt) {
    return ((uint8_t*)pkt->raw_buff) + sizeof(struct ethhdr);
}

/**
 * Given a bpfhv_pkt* pkt, return the ip header
 * return: ip header
*/
static inline struct iphdr*
get_ip_header(struct bpfhv_pkt* pkt) {
    return (struct iphdr*)get_eth_payload(pkt);
}

/**
 * Given a bpfhv_pkt* pkt, return the arp header
 * return: arp header
*/
static inline struct arphdr*
get_arp_header(struct bpfhv_pkt* pkt) {
    return (struct arphdr*)get_eth_payload(pkt);
}

/**
 * Given a bpfhv_pkt* pkt, return the arp body
 * return: arp body
*/
static inline struct arphdr*
get_arp_body(struct bpfhv_pkt* pkt) {
    return (struct arphdr*)((uint8_t*)pkt->raw_buff + sizeof(struct ethhdr) + sizeof(struct arphdr));
}

/**
 * Given a bpfhv_pkt* pkt, return the tcp header
 * return: tcp header
*/
static inline struct tcphdr*
get_tcp_header(struct bpfhv_pkt* pkt) {
    return (struct tcphdr*)((uint8_t*)pkt->raw_buff + sizeof(struct ethhdr) + sizeof(struct iphdr));
}

/**
 * Given a bpfhv_pkt* pkt, return the tcp header
 * return: udp header
*/
static inline struct udphdr*
get_udp_header(struct bpfhv_pkt* pkt) {
    return (struct udphdr*)((uint8_t*)pkt->raw_buff + sizeof(struct ethhdr) + sizeof(struct iphdr));
}

/**
 * Given a bpfhv_pkt* pkt, return true if the packet is not a valid ETH packet
 * return: true if the packet is not valid
*/
static inline bool
invalid_eth_pkt(struct bpfhv_pkt* pkt) {
    return (pkt->len < sizeof(struct ethhdr));
}

/**
 * Given a bpfhv_pkt* pkt, return false if the packet is a valid IP L3 packet
 * return: true if the packet is not valid
*/
static inline bool
invalid_ip_pkt(struct bpfhv_pkt* pkt) {
    return (pkt->len < sizeof(struct ethhdr) + sizeof(struct iphdr));
}

/**
 * Given a bpfhv_pkt* pkt, return false if the packet is a valid ARP packet
 * return: true if the packet is not valid
*/
static inline bool
invalid_arp_pkt(struct bpfhv_pkt* pkt) {
    return (pkt->len < sizeof(struct ethhdr) + sizeof(struct arphdr) + sizeof(struct arpethbody));
}

/**
 * Given 2 MAC addresses, check if they are equal
 * m1: first MAC address
 * m2: second MAC address
 * return: true if
*/
static inline bool
mac_equal(const uint8_t* m1, const uint8_t* m2) {
    return *((uint32_t*)m1) == *((uint32_t*)m2) && *((uint32_t*)(m1+4)) == *((uint32_t*)(m2+4));
}


#endif
