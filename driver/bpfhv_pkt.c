#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include "types.h"
#include "bpfhv_pkt.h"


#define ETH_ALEN 6


/**
 *	This structure defines an ethernet arp header.
 */
struct arphdr {
	__be16		ar_hrd;		/* format of hardware address	*/
	__be16		ar_pro;		/* format of protocol address	*/
	unsigned char	ar_hln;		/* length of hardware address	*/
	unsigned char	ar_pln;		/* length of protocol address	*/
	__be16		ar_op;		/* ARP opcode (command)		*/
};

/**
 *	This structure defines an ethernet arp body (ETH).
 */
struct arpethbody {
	uint8_t ar_sha[ETH_ALEN]; /* sender hardware address */
	__be32  ar_sip;           /* sender IP address */
	uint8_t ar_tha[ETH_ALEN]; /* target hardware address */
	__be32  ar_tip;           /* target IP address */
};


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
 * Docstring in bpfhv_pkt.h
 */
struct bpfhv_pkt*
skb_to_bpfvh_pkt(struct bpfhv_pkt* bpfhv_pkt, const struct sk_buff* skb) {
    if(unlikely(!bpfhv_pkt || !skb))
        return 0;

    bpfhv_pkt->raw_buff = skb->data;  //l2_header and eth_header
    bpfhv_pkt->len = skb->len;

    if(unlikely(bpfhv_pkt->len < sizeof(struct ethhdr))) {
        printk(KERN_ERR "skb_to_bpfvh_pkt(...) -> invalid bpfhv_pkt->len\n");
        return 0;
    }

    switch(be16_to_cpu(bpfhv_pkt->eth_header->h_proto)) {
        case ETH_P_IP:
            // Set IP header address
            //bpfhv_pkt->l3_header = skb_network_header(skb);
			bpfhv_pkt->ip_header = (struct iphdr*)(bpfhv_pkt->raw_buff + sizeof(struct ethhdr));
			if(unlikely(bpfhv_pkt->ip_header->version != 4)) {
				printk(
                    KERN_ERR "skb_to_bpfvh_pkt(...) -> bpfhv_pkt->ip_header->version: %d\n",
                    bpfhv_pkt->ip_header->version
                );
				return 0;
			}

            // Set TCP/UDP header address
            //bpfhv_pkt->l4_header = skb_transport_header(skb);
            bpfhv_pkt->l4_header = get_ip_payload(
                bpfhv_pkt->ip_header, bpfhv_pkt->len - sizeof(struct ethhdr)
            );
            if(unlikely(!bpfhv_pkt->l4_header))
                return 0;

            // Set payload address
			switch (bpfhv_pkt->ip_header->protocol) {
				case IPPROTO_UDP:
		            bpfhv_pkt->payload = get_udp_payload(bpfhv_pkt->udp_header);
					break;
		        case IPPROTO_TCP:
		            bpfhv_pkt->payload = get_tcp_payload(bpfhv_pkt->tcp_header);
					break;
		        case IPPROTO_ICMP:
		            return 0;
		        default:
					printk(KERN_ERR "skb_to_bpfvh_pkt(...) -> invalid bpfhv_pkt->ip_header->protocol\n");
		            return 0;
			}
			bpfhv_pkt->payload_len = bpfhv_pkt->len - ((uintptr_t)bpfhv_pkt->payload - (uintptr_t)bpfhv_pkt->raw_buff);
            break;
        case ETH_P_IPV6:
            return 0;
		case ETH_P_ARP:
            if(unlikely(
				bpfhv_pkt->len < sizeof(struct ethhdr) +
				sizeof(struct arphdr) + sizeof(struct arpethbody)
			)) {
				return 0;
			}
			bpfhv_pkt->arp_header = (struct arphdr*)(bpfhv_pkt->raw_buff + sizeof(struct ethhdr));
			bpfhv_pkt->arp_body = (struct arpethbody*)(
				(uintptr_t)bpfhv_pkt->arp_header + sizeof(struct arphdr)
			);
			bpfhv_pkt->payload = 0;
			bpfhv_pkt->payload_len = 0;
			break;
        default:
			printk(KERN_ERR "skb_to_bpfvh_pkt(...) -> invalid bpfhv_pkt->eth_header->h_proto\n");
            return 0;
    }

    return bpfhv_pkt;
}


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Federico Cappellini");
