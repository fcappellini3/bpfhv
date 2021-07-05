#ifndef __EBPF_IDS_COMMON_H__
#define __EBPF_IDS_COMMON_H__


// Common dependencies
#include "net_headers.h"
#include <stdint.h>


// Data types
typedef uint8_t bool;


#define IDS_INVALID_PKT 0xFFFFFFFFU
#define IDS_PASS        0x00U


#define IPADDR(a1,a2,a3,a4)    (uint32_t)((a1) << 24 | (a2) << 16 | (a3) << 8 | (a4))
#define IPADDR_BE(a1,a2,a3,a4)   (__be32)((a4) << 24 | (a3) << 16 | (a2) << 8 | (a1))

#define IDS_SUSPICIOUS_LEVEL(A) (A)


/**
 * Given a L2 packet, return the payload address
 * raw_pkt_data: start address of packet
 * return: payload address
*/
static inline uint8_t*
get_eth_payload(uint8_t* raw_pkt_data) {
    return raw_pkt_data + sizeof(struct ethhdr);
}

/**
 * Given a L2 packet, return the ip header
 * raw_pkt_data: start address of packet
 * return: payload address
*/
static inline struct iphdr*
get_ip_header(uint8_t* raw_pkt_data) {
    return (struct iphdr*)(raw_pkt_data + sizeof(struct ethhdr));
}

/**
 * Given a L2 packet size, return true if the packet is not valid
 * pkt_sz: packet size
 * return: true if the packet is not valid
*/
static inline bool
invalid_eth_pkt(const uint32_t pkt_sz) {
    return (pkt_sz < sizeof(struct ethhdr));
}

/**
 * Given a L2 packet, return the tcp header
 * raw_pkt_data: start address of packet
 * return: payload address
*/
static inline struct tcphdr*
get_tcp_header(uint8_t* raw_pkt_data) {
    return (struct tcphdr*)(raw_pkt_data + sizeof(struct ethhdr) + sizeof(struct iphdr));
}

/**
 * Given a L2 packet, return the tcp header
 * raw_pkt_data: start address of packet
 * return: payload address
*/
static inline struct udphdr*
get_udp_header(uint8_t* raw_pkt_data) {
    return (struct udphdr*)(raw_pkt_data + sizeof(struct ethhdr) + sizeof(struct iphdr));
}

/**
 * Given a L2 packet size, return false if the packet is a valid IP L3 packet
 * pkt_sz: packet size
 * return: true if the packet is not valid
*/
static inline bool
invalid_ip_pkt(const uint32_t pkt_sz) {
    return (pkt_sz < sizeof(struct ethhdr) + sizeof(struct iphdr));
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
