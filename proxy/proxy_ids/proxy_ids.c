#include <stdio.h>
#include "proxy_ids.h"
#include "bpfhv_pkt.h"
#include "net_headers.h"
#include "hashmap.h"
#include "bpfhv_ids_flow.h"


// bpfhv_pkt
static struct bpfhv_pkt global_bpfhv_pkt;

// Flow hashmap
#define h_key_t struct flow_id
#define h_value_t struct flow*
#define HASH_TABLE_SIZE 16
static uint32_t
hash(const h_key_t key) {
    return (uint32_t)(
        flow_id->src_ip ^ flow_id->dest_ip ^
        ((((flow_key_t)flow_id->src_port) << 16) ^ (flow_key_t)flow_id->dest_port) ^
        (flow_key_t)flow_id->protocol
    ) % HASH_TABLE_SIZE;
}
DECLARE_HASHMAP(flow_hashmap, HASH_TABLE_SIZE, hash);


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
			fprintf(stderr, "craft_bpfhv_pkt(...) -> invalid global_bpfhv_pkt.eth_header->h_proto\n");
            return 0;
    }

    return &global_bpfhv_pkt;
}

/**
 * Docstring in proxy_ids.h
 */
uint32_t
ids_analyze_eth_pkt(void* buff, uint32_t len) {
    struct bpfhv_pkt* bpfhv_pkt = craft_bpfhv_pkt(buff, len);
    if(!bpfhv_pkt)
        return 0;
}
