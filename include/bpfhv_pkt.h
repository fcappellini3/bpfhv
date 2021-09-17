#ifndef __BPFHV_PKT_H__
#define __BPFHV_PKT_H__


#include "types.h"


#define FLAG_BPFHV_PKT_NO_PARSE 0x1U


/**
 * bpfhv_tx_context and bpfhv_rx_context has a reference to the current sk_buff, but the BPF
 * program can not use it since it can not know the current definition of struct sk_buff.
 * This limitation makes our BPF program unable to perform (deep) packet inspection that is
 * exactly what we want to to in our IDS implementation.
 * As a workaround, standard eBPF programs can access struct __sk_buff that is a "mirror data
 * structure" for sk_buff known by eBPF programs and initialized/populated by the kernel staring
 * form a real sk_buff.
 * The same approach is used here, there struct bpfhv_pkt is representing the current packet.
 */
struct bpfhv_pkt {
	union {
		void* raw_buff;
		void* l2_header;
		struct ethhdr* eth_header;
	};
	union {
		void* l3_header;
		struct iphdr* ip_header;
		struct arphdr* arp_header;
	};
	union {
		void* l4_header;
		struct tcphdr* tcp_header;
		struct udphdr* udp_header;
		struct arpethbody* arp_body;
	};
	uint8_t* payload;
	uint32_t len;
	uint32_t payload_len;
};


#ifdef __KERNEL__  // Functions that follow are included when compiling for kernelspace

/**
 * Cast a struct bpfhv_pkt starting from an struct sk_buff
 */
struct bpfhv_pkt*
skb_to_bpfvh_pkt(struct bpfhv_pkt* bpfhv_pkt, const struct sk_buff* skb, const uint32_t flags);

#endif


#endif
