#ifndef __EBPF_IDS_H__
#define __EBPF_IDS_H__


// Includes
#include "ebpf_ids_common.h"
#include "auto_rules.h"

// Constants
#define DEFAULT_FLOW_SIZE (1*1024*1024)
#define MAX_STORE_SIZE (DEFAULT_FLOW_SIZE / 2)

// Macros
#define get_reserved_bpf(flow) ((struct reserved_bpf*)((flow)->reserved_bpf))
#define bpf2bpf_check_flow(A) bpf2bpf_call(BPFHV_PROG_EXTRA_0, (const void*)(A));

// Other includes
#include "examples/basic_pdt.h"
#include "examples/basic_deep_scan.h"
#include "examples/basic_check_flow.h"

#if 0
#include "examples/deep_scan_by_hash.h"
#endif


//static void check_flow(struct flow* flow);


/**
 * Apply IDS IP rules. This function must be called by ids_analyze_eth_pkt only.
 * This function assumes that pkt is a valid ETH IP packet.
 * pkt: current struct bpfhv_pkt*. Assumed not to be NULL.
 */
static __inline uint32_t
__ids_analyze_ip_pkt(struct bpfhv_pkt* pkt) {
    struct iphdr* ip_header = pkt->ip_header;
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
            print_debug(5);
            return IDS_PASS;
    }
}

/**
 * Apply IDS ARP rules. This function must be called by ids_analyze_eth_pkt only.
 * This function assumes that pkt is a valid APR (ETH) packet.
 * pkt: current struct bpfhv_pkt*. Assumed not to be NULL.
 */
static __inline uint32_t
__ids_analyze_arp_pkt(struct bpfhv_pkt* pkt) {
#if 0
    struct arphdr* arp_header = pkt->arp_header;
    if(arp_header->ar_hln != 6 && arp_header->ar_pln != 4) {
        print_debug(2);
        return IDS_INVALID_PKT(2);
    }
#endif
#if 0
    // Example of APR poisoning detection
    struct arpethbody* arp_body = pkt->arp_body;
    if(!arp_body) {
        print_debug(2);
        return IDS_INVALID_PKT(3);
    }
    if(
        arp_body->ar_sip == GATEWAY_IP &&
        !mac_equal(arp_body->ar_sha, GATEWAY_MAC)
    ) {
        return IDS_LEVEL(10);
    }
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
 * This function assumes that pkt is a valid eth packet and does not perform checks.
 * pkt: current struct bpfhv_pkt*. Assumed not to be NULL.
 * return: IDS analyzis resulting level
 */
static __inline uint32_t
ids_analyze_eth_pkt(struct bpfhv_rx_context* ctx, struct bpfhv_pkt* pkt) {
    // L2 rules
    uint32_t l2_check = __ids_l2_rules(pkt);
    if(l2_check != IDS_PASS)
        return l2_check;

    // The next step depends on the L3 protocol written in the L2 header
    uint16_t proto = be16_to_cpu(pkt->eth_header->h_proto);
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
            print_debug(1);
            result = IDS_INVALID_PKT(1);
            break;
    }

    // If result is not IDS_PASS, the result must be returned immediately before everything else
    // in order to drop the packet
    if(result != IDS_PASS)
        return result;

    // In case the previous analyzes returned IDS_PASS and the current packet is an IP packet, it
    // has to be object of a deep scan
    if(proto == ETH_P_IP)
        result = __ids_deep_scan(ctx, pkt);

    return result;
}

/**
 * Call ids_analyze_eth_pkt(...) based on current bpfhv_rx_context
 * return: IDS analyzis resulting level
 */
static __inline uint32_t
ids_analyze_eth_pkt_by_context(struct bpfhv_rx_context* ctx) {
    uint32_t level;

    struct bpfhv_pkt* pkt = get_bpfhv_pkt(ctx, 0);
    if(!pkt)
        return IDS_PASS;

    level = ids_analyze_eth_pkt(ctx, pkt);

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

#ifdef IDS

/**
 * Receive post process handler (rxh)
 * return: BPFHV_PROG_RX_POSTPROC_PKT_DROP to signal that the packet must be dropped or
 *         BPFHV_PROG_RX_POSTPROC_OK to signal that the packet is legit and can be forwarded to
 *         higher levels of the network stack
 */
__section("rxh")
int
rxh_handler(struct bpfhv_rx_context *ctx)
{
    uint32_t level = ids_analyze_eth_pkt_by_context(ctx);
    if(IS_CRITICAL(level))
        return BPFHV_PROG_RX_POSTPROC_PKT_DROP;
    return BPFHV_PROG_RX_POSTPROC_OK;
}

/**
 * This "hadler" is called whenever a socket is released.
 * In this case the only thing we have to do is to delete the corresponding flow.
 * flow_id: flow_id that corresponds to the releasing socket.
 */
__section("srl")
int
socket_released_handler(struct flow_id* flow_id) {
    delete_flow(flow_id);
    return 0;
}

/**
 * This handler is called whenever something reads from a socket that is related to a flow managed
 * by the current instance of BPFHV
 */
__section("srd")
uint32_t
socket_read_handler(struct srd_handler_arg* arg) {
    uint32_t i;
    uint32_t store_result;
    uint32_t stored_size = 0;
    byte* buff;
    uint32_t len;
    uint32_t step_len;

    // Store in the flow everything in arg (max len per store: MAX_STORE_SIZE)
    for(i = 0; i < arg->buffer_descriptor_array_size; ++i) {
        buff = (byte*)arg->buffer_descriptor_array[i].buff;
        len = arg->buffer_descriptor_array[i].len;
        while(len) {
            step_len = MIN(len, MAX_STORE_SIZE);
            store_result = store_pkt(arg->flow, buff, step_len);
            if(unlikely(store_result != STORE_PKT_SUCCESS)) {
                print_debug(6);
                break;
            }
            get_reserved_bpf(arg->flow)->bytes_stored_from_last_check += step_len;
            stored_size += step_len;
            buff += step_len;
            len -= step_len;

            // If enough bytes are stored perform a check
            if(get_reserved_bpf(arg->flow)->bytes_stored_from_last_check >= MAX_STORE_SIZE) {
                bpf2bpf_check_flow(arg->flow);
            }
        }
    }

    // Perform flow checking at the end independently of bytes_stored_from_last_check
    bpf2bpf_check_flow(arg->flow);

    return stored_size;
}

/**
 * Check a flow w.r.t. its own struct ids_capture_protocol.
 * Send a signal to the hypervisor in case of a match.
 * Reset bytes_stored_from_last_check.
 */
__section("extra0")
static void
check_flow(struct flow* flow) {
    if(unlikely(__check_flow(flow, get_reserved_bpf(flow)->cap_prot))) {
        char str[32];
        str[0]='F'; str[1]='l'; str[2]='o'; str[3]='w'; str[4]=' '; str[5]='c'; str[6]='h'; str[7]='e'; str[8]='c'; str[9]='k'; str[10]=' '; str[11]='r'; str[12]='e'; str[13]='s'; str[14]='u'; str[15]='l'; str[16]='t'; str[17]=0;
        print_num(str, IDS_LEVEL(get_reserved_bpf(flow)->cap_prot->ids_level));
        send_hypervisor_signal(
            flow->owner_bpfhv_info,
            0,
            IDS_LEVEL(get_reserved_bpf(flow)->cap_prot->ids_level)
        );
    }
    get_reserved_bpf(flow)->bytes_stored_from_last_check = 0;
}

#endif

#endif
