/**
 * Basic example of __check_flow(...). This is the one used for performance evaluation.
 */


/**
 * Check a flow w.r.t. a struct ids_capture_protocol.
 * return: true if flow match the condition of cap_prot, false otherwise.
 */
static __inline bool
__check_flow(struct flow* flow, struct ids_capture_protocol* cap_prot) {
    struct flow_iter iter;
    struct flow_iter iter_copy;
    byte* ptr;
    uint32_t i;

    for(ptr = iter_init(&iter, flow); ptr; ptr = iter_next(&iter)) {
        iter_copy = iter;
        for(i = 0; ptr && i < cap_prot->payload_size; ptr = iter_next(&iter_copy), ++i) {
            if(*ptr != cap_prot->payload[i]) {
                break;
            }
        }
        if(i == cap_prot->payload_size && ptr) {
            return true;
        }
    }

    return false;
}
