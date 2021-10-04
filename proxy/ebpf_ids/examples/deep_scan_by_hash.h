/**
 * Example of __ids_deep_scan(...) that uses an hash function to check match rules
 */


#define ALARM_COUNT 6

#define PAYLOAD_0 { \
        0x00, 0x01, 0x02, 0x03, 0x04, 0x00, 0x01, 0x02, \
        0x03, 0x04, 0x00, 0x01, 0x02, 0x03, 0x04, 0x00, \
        0x01, 0x02, 0x03, 0x04, 0x00, 0x01, 0x02, 0x03, \
        0x04, 0x00, 0x01, 0x02, 0x03, 0x04, 0x00, 0x01, \
        0x02, 0x03, 0x04, 0x00, 0x01, 0x02, 0x03, 0x04, \
        0x00, 0x01, 0x02, 0x03, 0x04, 0x00, 0x01, 0x02, \
        0x03, 0x04, 0x00, 0x01, 0x02, 0x03, 0x04, 0x00, \
        0x01, 0x02, 0x03, 0x04, 0x00, 0x01, 0x02, 0x03  \
    }
#define PAYLOAD_1 { \
        0x10, 0x01, 0x02, 0x03, 0x14, 0x00, 0x01, 0x02, \
        0x03, 0x04, 0x00, 0x01, 0x02, 0x03, 0x04, 0x00, \
        0x01, 0x02, 0x03, 0x04, 0x10, 0x01, 0x02, 0x03, \
        0x04, 0x00, 0x01, 0x02, 0x03, 0x04, 0x00, 0x01, \
        0x02, 0x03, 0x04, 0x00, 0x11, 0x02, 0x03, 0x04, \
        0x00, 0x01, 0x02, 0x03, 0x04, 0x00, 0x01, 0x02, \
        0x03, 0x04, 0x00, 0x01, 0x02, 0x03, 0x04, 0x00, \
        0x11, 0x02, 0x03, 0x04, 0x10, 0x01, 0x02, 0x03  \
    }
#define PAYLOAD_2 { \
        0x00, 0x21, 0x02, 0x03, 0x04, 0x00, 0x21, 0x02, \
        0x03, 0x24, 0x00, 0x01, 0x02, 0x03, 0x24, 0x00, \
        0x01, 0x22, 0x03, 0x04, 0x00, 0x01, 0x22, 0x03, \
        0x04, 0x20, 0x01, 0x02, 0x03, 0x04, 0x20, 0x01, \
        0x02, 0x23, 0x04, 0x00, 0x01, 0x02, 0x23, 0x04, \
        0x00, 0x21, 0x02, 0x03, 0x04, 0x00, 0x21, 0x02, \
        0x03, 0x24, 0x00, 0x01, 0x02, 0x03, 0x24, 0x00, \
        0x01, 0x22, 0x03, 0x04, 0x00, 0x01, 0x22, 0x03  \
    }
#define PAYLOAD_3 { \
        0x00, 0x01, 0x02, 0x33, 0x04, 0x00, 0x01, 0x02, \
        0x03, 0x04, 0x00, 0x31, 0x02, 0x03, 0x04, 0x00, \
        0x01, 0x02, 0x03, 0x34, 0x00, 0x01, 0x02, 0x03, \
        0x04, 0x00, 0x01, 0x32, 0x03, 0x04, 0x00, 0x01, \
        0x02, 0x03, 0x04, 0x30, 0x01, 0x02, 0x03, 0x04, \
        0x00, 0x01, 0x02, 0x33, 0x04, 0x00, 0x01, 0x02, \
        0x03, 0x04, 0x00, 0x31, 0x02, 0x03, 0x04, 0x00, \
        0x01, 0x02, 0x03, 0x34, 0x00, 0x01, 0x02, 0x03  \
    }
#define PAYLOAD_4 { \
        0x00, 0x41, 0x02, 0x33, 0x04, 0x00, 0x01, 0x42, \
        0x03, 0x44, 0x00, 0x31, 0x02, 0x03, 0x04, 0x40, \
        0x01, 0x42, 0x03, 0x34, 0x00, 0x01, 0x02, 0x43, \
        0x04, 0x40, 0x01, 0x32, 0x03, 0x04, 0x00, 0x41, \
        0x02, 0x43, 0x04, 0x30, 0x01, 0x02, 0x03, 0x44, \
        0x00, 0x41, 0x02, 0x33, 0x04, 0x00, 0x01, 0x42, \
        0x03, 0x44, 0x00, 0x31, 0x02, 0x03, 0x04, 0x40, \
        0x01, 0x42, 0x03, 0x34, 0x00, 0x01, 0x02, 0x43  \
    }
#define PAYLOAD_5 { \
        0x50, 0x01, 0x02, 0x33, 0x04, 0x00, 0x01, 0x02, \
        0x53, 0x04, 0x00, 0x31, 0x02, 0x03, 0x04, 0x00, \
        0x51, 0x02, 0x03, 0x34, 0x00, 0x01, 0x02, 0x03, \
        0x04, 0x00, 0x01, 0x52, 0x03, 0x04, 0x00, 0x01, \
        0x02, 0x03, 0x04, 0x50, 0x01, 0x02, 0x03, 0x04, \
        0x00, 0x01, 0x02, 0x33, 0x54, 0x00, 0x01, 0x02, \
        0x03, 0x04, 0x00, 0x31, 0x02, 0x53, 0x54, 0x50, \
        0x01, 0x02, 0x03, 0x34, 0x00, 0x01, 0x02, 0x53  \
    }


struct global {
    uint32_t alarm_count;
    struct ids_alarm alarms[ALARM_COUNT];
    struct ids_capture_protocol cap_protos[1];
    byte hash_buffer[512];
};

 __section("pdt")
 struct global global_ = {
     .alarm_count = ALARM_COUNT,
     .alarms = {
         {
             .cap_prot_index = 0,
             .payload_size = 64,
             .payload = PAYLOAD_0,
             .action = CAPTURE
         },
         {
             .cap_prot_index = 0,
             .payload_size = 5,
             .payload = PAYLOAD_1,
             .action = CAPTURE
         },
         {
             .cap_prot_index = 0,
             .payload_size = 5,
             .payload = PAYLOAD_2,
             .action = CAPTURE
         },
         {
             .cap_prot_index = 0,
             .payload_size = 5,
             .payload = PAYLOAD_3,
             .action = CAPTURE
         },
         {
             .cap_prot_index = 0,
             .payload_size = 5,
             .payload = PAYLOAD_4,
             .action = CAPTURE
         },
         {
             .cap_prot_index = 0,
             .payload_size = 5,
             .payload = PAYLOAD_5,
             .action = CAPTURE
         }
     },
     .cap_protos = {
         {
             .payload_size = 7,
             .ids_level = 9,
             .payload = {'/', 'b', 'a', 'd', '_', 'e', 'p'},
             .action = DROP_FLOW
         }
     }
 };


static __inline bool
compare_hash(const byte* hash_a, const byte* hash_b) {
    uint64_t* a = (uint64_t*)hash_a;
    uint64_t* b = (uint64_t*)hash_b;
    uint32_t i;

    for(i = 0; i < 8; ++i, ++a, ++b) {
        if(likely(*a != *b)) {
            return false;
        }
    }

    return true;
}


/**
 * Compute the 512 bit hash (64 bytes) of the payload of pkt.
 * buffer: a buffer to store the result, has to have a lenght greater or equal to 64 bytes.
 * return: a pointer to the computer hash
 */
static __inline byte*
compute_hash(struct bpfhv_pkt* pkt, void* buffer) {
    uint64_t* buff = (uint64_t*)buffer;
    uint32_t steps = (pkt->payload_len / (sizeof(uint64_t))) >> 3;
    uint64_t* ptr = (uint64_t*)pkt->payload;
    uint32_t i;
    byte magic_index;

    // Initial state
    buff[0] = 0x1122334455667788ULL;
    buff[1] = 0x00DDEEFFAA112233ULL;
    buff[2] = 0x0000000000000000ULL;
    buff[3] = 0x1122334455667788ULL;
    buff[4] = 0x1122334455667788ULL;
    buff[5] = 0x0000000000000000ULL;
    buff[6] = 0x00DDEEFFAA112233ULL;
    buff[7] = 0x1122334455667788ULL;

    // Hash calculation by byte blocks (1 byte block = 8 uint64_t = 64 bytes)
    while(steps) {
        if(steps & 0b1) {
            for(i = 0; i < 8; ++i) {
                buff[i] ^= ptr[i];
            }
        } else {
            for(i = 0; i < 8; ++i) {
                buff[7-i] ^= ~ptr[i];
            }
        }
        magic_index = ((uint8_t*)buff)[steps & 0b111111] & 0b111111;   // [0;63]
        magic_index = ((uint8_t*)buff)[magic_index] & 0b11111;         // [0;31]
        ((uint16_t*)buff)[magic_index] ^= ((uint16_t*)buff)[31-magic_index];
        ptr += 8;
        --steps;
    }

    // Remaining bytes. They're less or equal to than 7 * 8 = 64 (7 copies of uint64_t, so 7 copies
    // of groups of 8 bytes).
    steps = (uint32_t)(
        (uintptr_t)pkt->payload + (uintptr_t)pkt->payload_len - (uintptr_t)ptr
    );
    for(i = 0; i < steps; ++i) {
        ((byte*)buff)[i % 64] ^= ((byte*)ptr)[i];
    }

    return (byte*)buff;
}

/**
 * Deep scan the packet
 * pkt: current struct bpfhv_pkt*. Assumed not to be NULL and to be a valid ip packet.
 */
 static __inline uint32_t
 __ids_deep_scan(struct bpfhv_rx_context* ctx, struct bpfhv_pkt* pkt) {
     uint32_t alarm_index;
     struct ids_capture_protocol* cap_prot;
     struct flow_id flow_id;
     struct tcphdr* tcp_header;
     struct udphdr* udp_header;
     struct flow* flow;

     // Get global memory
     struct global* global = get_shared_memory();

     // Find packet payload and flow_id
     struct iphdr* ip_header = pkt->ip_header;
     if(ip_header->version != 4) {
         return IDS_PASS;
     }
     flow_id.src_ip = ip_header->saddr;
     flow_id.dest_ip = ip_header->daddr;
     flow_id.protocol = ip_header->protocol;
     switch(ip_header->protocol) {
         case IPPROTO_UDP:
             udp_header = pkt->udp_header;
             flow_id.src_port = udp_header->source;
             flow_id.dest_port = udp_header->dest;
             break;
         case IPPROTO_TCP:
             tcp_header = pkt->tcp_header;
             flow_id.src_port = tcp_header->source;
             flow_id.dest_port = tcp_header->dest;
             break;
         default:
             return IDS_PASS;
     }
     if(!pkt->payload) {
        print_debug(4);
        return IDS_INVALID_PKT(4);
    }

     // Check if a flow already exists. If it exists we don't have to check for a matching payload,
     // but if there is no flow, we have to search for a matching payload (and maybe start a new
     // flow in case we found one).
     flow = get_flow(&flow_id);
     if(flow) {
         goto a_flow_exists;
     } else {
         // Compute hash
         compute_hash(pkt, &(global->hash_buffer[0]));

         // Scan for a matching hash
         for(alarm_index = 0; alarm_index < global->alarm_count; ++alarm_index) {
             struct ids_alarm* alarm = &global->alarms[alarm_index];
             if(unlikely(compare_hash(&(global->hash_buffer[0]), alarm->payload))) {
                 // The current pkt matched an alarm
                 char s[32]; s[0] = 'f'; s[1] = 'o'; s[2] = 'u'; s[3] = 'n'; s[4] = 'd'; s[5] = ' ';
                 s[6] = 'a'; s[7] = 't'; s[8] = 0;
                 print_num(s, 0);

                 // If alarm->action is DROP, the packet must be immediatel dropped!
                 if(alarm->action == DROP) {
                     return IDS_LEVEL(10);
                 }

                 // Otherwise, let's chek for the capture protocol and procede to create a new flow
                 cap_prot = &global->cap_protos[alarm->cap_prot_index];
                 flow = create_flow(&flow_id, true, DEFAULT_FLOW_SIZE, ctx);
                 if(!flow) {
                     return IDS_LEVEL(10);
                 }
                 get_reserved_bpf(flow)->cap_prot = cap_prot;
                 get_reserved_bpf(flow)->bytes_stored_from_last_check = 0;
                 goto a_flow_exists;
             }
         }

         // If no payloads were found and no flows were found, this packet is legit
         return IDS_PASS;
     }

     a_flow_exists:
     // If I'm here a flow exists (because it was just created or because it was already existing).
     // Flow checking and deleating are managed later

     return IDS_PASS;
 }
