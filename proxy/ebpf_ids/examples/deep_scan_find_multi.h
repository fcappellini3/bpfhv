/**
 * Example of __ids_deep_scan(...) that uses the helper function find_multi(...)
 */


#define ALARM_COUNT 6

struct global {
    uint32_t alarm_count;
    struct ids_alarm alarms[ALARM_COUNT];
    struct ids_capture_protocol cap_protos[1];
};

__section("pdt")
struct global global_ = {
    .alarm_count = ALARM_COUNT,
    .alarms = {
        {
            .cap_prot_index = 0,
            .payload_size = 5,
            .payload = {'H', 'T', 'T', 'P', '/'},
            .action = CAPTURE
        },
        {
            .cap_prot_index = 0,
            .payload_size = 5,
            .payload = {'a', 'b', 'c', 'd', ':'},
            .action = CAPTURE
        },
        {
            .cap_prot_index = 0,
            .payload_size = 5,
            .payload = {'A', 'B', 'C', 'D', 'E'},
            .action = CAPTURE
        },
        {
            .cap_prot_index = 0,
            .payload_size = 5,
            .payload = {'e', 'd', 'c', 'b', 'a'},
            .action = CAPTURE
        },
        {
            .cap_prot_index = 0,
            .payload_size = 5,
            .payload = {'E', 'D', 'C', 'B', 'A'},
            .action = CAPTURE
        },
        {
            .cap_prot_index = 0,
            .payload_size = 5,
            .payload = {':', '?', '^', '@', '#'},
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
         // Scan: search for an "alarm payload" inside pkt->payload
         uint64_t find_multi_res;
         struct buffer_descriptor where = {.buff = pkt->payload, .len = pkt->payload_len};
         struct buffer_descriptor whats[10];
         struct ids_alarm* alarm;
         for(alarm_index = 0; alarm_index < global->alarm_count; ++alarm_index) {
             alarm = &global->alarms[alarm_index];
             whats[alarm_index].buff = alarm->payload;
             whats[alarm_index].len = alarm->payload_size;
         }
         find_multi_res = find_multi(&where, &whats[0], global->alarm_count);
         if(unlikely(find_multi_res != NOT_FOUND)) {
             // The current pkt matched an alarm
             char s[32]; s[0] = 'f'; s[1] = 'o'; s[2] = 'u'; s[3] = 'n'; s[4] = 'd'; s[5] = ' ';
             s[6] = 'a'; s[7] = 't'; s[8] = 0;
             print_num(s, find_multi_res & 0xFFFFFFFFU);

             alarm = &global->alarms[find_multi_res >> 32];

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

         // If no payloads were found and no flows were found, this packet is legit
         return IDS_PASS;
     }

     a_flow_exists:
     // If I'm here a flow exists (because it was just created or because it was already existing).
     // Flow checking and deleating are managed later

     return IDS_PASS;
 }
