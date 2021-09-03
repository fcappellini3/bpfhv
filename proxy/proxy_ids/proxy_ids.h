/**
 * This module provide an "equivalent" version of the EBPF IDS that can be compiled in userspace
 * with the proxy backend program and must be used for test pourposes only
 */


#ifndef __PROXY_IDS_H__
#define __PROXY_IDS_H__


#include "types.h"


// Constants //
#define IDS_PASS        0x00U
#define MAX_IDS_ALARM_PAYLOAD_SIZE 128
#define MAX_IDS_CAP_PROT_PAYLOAD_SIZE 128
#define IDS_CRITICAL_THRESHOLD 5

// Macros //
#define IPADDR(a1,a2,a3,a4)    (uint32_t)((a1) << 24 | (a2) << 16 | (a3) << 8 | (a4))
#define IPADDR_BE(a1,a2,a3,a4)   (__be32)((a4) << 24 | (a3) << 16 | (a2) << 8 | (a1))
#define IDS_LEVEL(A) (A)
#define IDS_INVALID_PKT(REASON) (0xFFFFFF00U | ((REASON) & 0xFFU))
#define IS_INVALID(A) (((A) & 0xFFFFFF00U) == IDS_INVALID_PKT(0))
#define IS_CRITICAL(A) ((A) > IDS_CRITICAL_THRESHOLD && !IS_INVALID(A))


/**
 * Start the ETH packet process. The packet must be described by the pointer to its buffer and
 * by an unsigned representing its length
 */
uint32_t ids_analyze_eth_pkt(void* buff, uint32_t len);


#endif
