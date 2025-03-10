#ifndef __EBPF_IDS_COMMON_H__
#define __EBPF_IDS_COMMON_H__


// Common dependencies //
#include <stdint.h>
#include "progs_common.h"
#include "net_headers.h"
#include "bpfhv_pkt.h"
#include "bpfhv_ids_flow.h"


// Helper functions //
static struct bpfhv_pkt* BPFHV_FUNC(get_bpfhv_pkt, struct bpfhv_rx_context *ctx, const uint32_t flags);
static int BPFHV_FUNC(print_num, const char* str, long long int x);
static void* BPFHV_FUNC(get_shared_memory);
static struct flow* BPFHV_FUNC(get_flow, struct flow_id* flow_id);
static struct flow* BPFHV_FUNC(create_flow, const struct flow_id* flow_id, const bool recording_enabled, const uint32_t max_size, struct bpfhv_rx_context* ctx);
static bool BPFHV_FUNC(delete_flow, struct flow_id* flow_id);
static uint32_t BPFHV_FUNC(store_pkt, struct flow* flow, void* buff, const uint32_t len);
static void BPFHV_FUNC(send_hypervisor_signal, struct bpfhv_info* bi, const uint32_t signal_id, const uint32_t value);
static uint32_t BPFHV_FUNC(find, const byte* where, const uint32_t where_size, const byte* what, const uint32_t what_size);
static uint32_t BPFHV_FUNC(find_multi, const struct buffer_descriptor* where, const struct buffer_descriptor* whats, const uint32_t whats_size);


// Constants //
#define IDS_PASS        0x00U
#define MAX_IDS_ALARM_PAYLOAD_SIZE 128
#define MAX_IDS_CAP_PROT_PAYLOAD_SIZE 128
#define IDS_CRITICAL_THRESHOLD 5


// Macros //
#define MIN(A, B) ((A) < (B) ? (A) : (B))
#define IPADDR(a1,a2,a3,a4)    (uint32_t)((a1) << 24 | (a2) << 16 | (a3) << 8 | (a4))
#define IPADDR_BE(a1,a2,a3,a4)   (__be32)((a4) << 24 | (a3) << 16 | (a2) << 8 | (a1))
#define IDS_LEVEL(A) (A)
#define IDS_INVALID_PKT(REASON) (0xFFFFFF00U | ((REASON) & 0xFFU))
#define IS_INVALID(A) (((A) & 0xFFFFFF00U) == IDS_INVALID_PKT(0))
#define IS_CRITICAL(A) ((A) > IDS_CRITICAL_THRESHOLD && !IS_INVALID(A))


// Data structures //
struct reserved_bpf {
    struct ids_capture_protocol* cap_prot;
    uint32_t bytes_stored_from_last_check;
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


/**
 * Given a bpfhv_pkt* pkt, return the ethernet header
 * return: ethernet header
 */
static __inline struct ethhdr*
get_eth_header(struct bpfhv_pkt* pkt) {
    return (struct ethhdr*)pkt->raw_buff;
}

/**
 * Given a bpfhv_pkt* pkt, return the payload address
 * return: ethernet payload
 */
static __inline byte*
get_eth_payload(struct bpfhv_pkt* pkt) {
    return ((uint8_t*)pkt->raw_buff) + sizeof(struct ethhdr);
}

/**
 * Given a bpfhv_pkt* pkt, return the ip header
 * return: ip header
 */
static __inline struct iphdr*
get_ip_header(struct bpfhv_pkt* pkt) {
    return (struct iphdr*)get_eth_payload(pkt);
}

/**
 * Given a bpfhv_pkt* pkt, return the arp header
 * return: arp header
 */
static __inline struct arphdr*
get_arp_header(struct bpfhv_pkt* pkt) {
    return (struct arphdr*)get_eth_payload(pkt);
}

/**
 * Given a bpfhv_pkt* pkt, return the arp body
 * return: arp body
 */
static __inline struct arphdr*
get_arp_body(struct bpfhv_pkt* pkt) {
    return (struct arphdr*)((uint8_t*)pkt->raw_buff + sizeof(struct ethhdr) + sizeof(struct arphdr));
}

/**
 * Given a  bpfhv_pkt* pkt, return the IP payload (that can be an UDP or TCP header)
 * return: IP payload
 */
 static __inline byte*
 get_ip_payload(struct bpfhv_pkt* pkt) {
     struct iphdr* ip_header = get_ip_header(pkt);
     uint32_t jump = sizeof(struct ethhdr) + (ip_header->ihl << 2);
     if(jump > pkt->len) {
         return 0;
     }
     return (byte*)pkt->raw_buff + jump;
     //return (byte*)pkt->raw_buff + sizeof(struct ethhdr) + sizeof(struct iphdr);
 }

/**
 * Given a bpfhv_pkt* pkt, return the tcp header
 * return: tcp header
 */
static __inline struct tcphdr*
get_tcp_header(struct bpfhv_pkt* pkt) {
    return (struct tcphdr*)get_ip_payload(pkt);
}

/**
 * Given a bpfhv_pkt* pkt, return the udp header
 * return: udp header
 */
static __inline struct udphdr*
get_udp_header(struct bpfhv_pkt* pkt) {
    return (struct udphdr*)get_ip_payload(pkt);
}

/**
 * Given a bpfhv_pkt* pkt, return the tcp payload
 * pkt: the bpfhv_pkt
 * payload_size: if not NULL, write the payload size to this address
 * return: tcp payload
 */
static __inline byte*
get_tcp_payload(struct bpfhv_pkt* pkt, uint32_t* payload_size) {
    struct tcphdr* tcp_header = get_tcp_header(pkt);
    uint32_t jump = (uintptr_t)tcp_header - (uintptr_t)pkt->raw_buff + (tcp_header->doff << 2);
    if(jump > pkt->len) {
        if(payload_size)
            *payload_size = 0;
        return 0;
    }
    if(payload_size)
        *payload_size = pkt->len - jump;
    return (byte*)pkt->raw_buff + jump;
}

/**
 * Given a bpfhv_pkt* pkt, return the udp payload
 * pkt: the bpfhv_pkt
 * payload_size: if not NULL, write the payload size to this address
 * return: udp payload
 */
static __inline byte*
get_udp_payload(struct bpfhv_pkt* pkt, uint32_t* payload_size) {
    const uint32_t jump = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
    if(payload_size)
        *payload_size = pkt->len - jump;
    return (byte*)pkt->raw_buff + jump;
}

/**
 * Given a bpfhv_pkt* pkt, return true if the packet is not a valid ETH packet
 * return: true if the packet is not valid
 */
static __inline bool
invalid_eth_pkt(struct bpfhv_pkt* pkt) {
    return (pkt->len < sizeof(struct ethhdr));
}

/**
 * Given a bpfhv_pkt* pkt, return false if the packet is a valid IP L3 packet
 * return: true if the packet is not valid
 */
static __inline bool
invalid_ip_pkt(struct bpfhv_pkt* pkt) {
    return (pkt->len < sizeof(struct ethhdr) + sizeof(struct iphdr));
}

/**
 * Given a bpfhv_pkt* pkt, return false if the packet is a valid ARP packet
 * return: true if the packet is not valid
 */
static __inline bool
invalid_arp_pkt(struct bpfhv_pkt* pkt) {
    return (pkt->len < sizeof(struct ethhdr) + sizeof(struct arphdr) + sizeof(struct arpethbody));
}

/**
 * Given 2 MAC addresses, check if they are equal
 * m1: first MAC address
 * m2: second MAC address
 * return: true if
 */
static __inline bool
mac_equal(const uint8_t* m1, const uint8_t* m2) {
    return *((uint32_t*)m1) == *((uint32_t*)m2) && *((uint32_t*)(m1+4)) == *((uint32_t*)(m2+4));
}

/**
 * Debug only: print an error code
 */
static __inline void
print_debug(const uint32_t code) {
    char str[32];
    str[0]='D'; str[1]='e'; str[2]='b'; str[3]='u'; str[4]='g'; str[5]=' '; str[6]='c'; str[7]='o'; str[8]='d'; str[9]='e'; str[10]=0;
    print_num(str, code);
}

#endif
