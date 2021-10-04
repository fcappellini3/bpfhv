/**
 * Example of __check_flow(...) used to spot the example case of an XSS attack
 */


#define ALARM_COUNT 1

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
            .payload_size = 16,
            .payload = {'G', 'E', 'T', ' ', '/', 'v', 'u', 'l', 'n', 'e', 'r', 'a', 'b', 'l', 'e', '?'},
            .action = CAPTURE
        }
    },
    .cap_protos = {
        {
            .payload_size = 15,
            .ids_level = 10,
            .payload = {
                'G', 'E', 'T', ' ', '/', 'v', 'u', 'l', 'n', 'e', 'r', 'a', 'b', 'l', 'e',
                'v', 'a', 'r', '\0',
                '%', '3', 'C', 's', 'c', 'r', 'i', 'p', 't', '%', '3', 'E', '\0'
            },
            .action = DROP_FLOW
        }
    }
};


static __inline bool
__start_with(struct flow_iter* iter, const byte* what, uint32_t what_size) {
    byte* ptr;
    struct flow_iter iter_copy = *iter;

    if(unlikely(!what_size)) {
        return true;
    }

    for(ptr = iter_current(&iter_copy); ptr; ptr = iter_next(&iter_copy)) {
        if(likely(*ptr != *what)) {
            return false;
        }
        ++what;
        --what_size;
        if(unlikely(!what_size)) {
            return true;
        }
    }

    return false;
}

/**
 * If iter points to a list on key/value HTTP query pairs, this function search for the key/value
 * query pair whose key is query_var_name and return the associated value.
 * A valid list is like this:
 *     ?var1=val1&var2=val2&var3=val3...
 * iter: flow_iter to the flow in exam
 * query_var_name: name (string) of the key to search for
 * value: output buffer, it has to be larger than or as large as the expected strlen(output) + 1 and
 *        strlen(query_var_name) + 3
 * return: pointer to the string containing the value or NULL in case no key/value pairs were fond
 *         whose key was query_var_name
 */
static __inline char*
__url_query_value(struct flow_iter* iter, const char* query_var_name, char* value) {
    char* ptr;
    char* query_var = value;
    uint32_t query_var_len = bpf_strlen(query_var_name);
    uint32_t i;

    // Check if iter point to a valid list
    if(unlikely(*((char*)iter_current(iter)) != '?')) {
        return NULL;
    }

    // Forge query_var
    query_var[0] = '?';
    bpf_memcpy(query_var + 1, query_var_name, query_var_len);
    query_var[query_var_len + 1] = '=';
    query_var[query_var_len + 2] = '\0';
    query_var_len += 2;

    // Check if query_var is in the first key/value pair
    if(unlikely(__start_with(iter, (byte*)query_var, query_var_len))) {
        goto found;
    }

    // 2nd, 3rd, 4th.... keys are preceded by '&' and not '?'
    query_var[0] = '&';

    // Check if query_var is in the key/value pair list
    for(ptr = (char*)iter_current(iter); ptr; ptr = (char*)iter_next(iter)) {
        // Stop at the end of the line of the HTTP request header
        if(unlikely(*ptr == '\n' || *ptr == '\r')) {
            return NULL;
        }

        if(unlikely(__start_with(iter, (byte*)query_var, query_var_len))) {
            goto found;
        }
    }

    return NULL;

    found:
    // Skip the '?' or '&' sign, the query_var_name and the '=' sign
    for(i = 0; i < query_var_len; ++i) {
        ptr = (char*)iter_next(iter);
    }

    // Copy the value (until an end mark) into value
    for(
        i = 0;
        ptr && (*ptr != '\0' && *ptr != '\n' && *ptr != '\r' && *ptr != '&');
        ++i, ptr = (char*)iter_next(iter)
    ) {
        value[i] = *ptr;
    }
    value[i] = '\0';

    return value;
}


/**
 * Check a flow (example case of an XSS attack)
 */
static __inline bool
__check_flow(struct flow* flow, struct ids_capture_protocol* cap_prot) {
    struct flow_iter iter;
    struct flow_iter iter_copy;
    byte* ptr;
    uint32_t i;

    // Search the payload in the flow
    for(ptr = iter_init(&iter, flow); ptr; ptr = iter_next(&iter)) {
        iter_copy = iter;
        for(i = 0; ptr && i < cap_prot->payload_size; ptr = iter_next(&iter_copy), ++i) {
            if(*ptr != cap_prot->payload[i]) {
                break;
            }
        }
        if(i == cap_prot->payload_size) {
            // If here the payload is in the flow. iter_copy points to the start of the list of
            // key/value HTTP query pairs. Let's retrieve query_var_value (if present) and check if
            // it contains a script tag.
            char buffer[128];
            char* query_var_name = (char*)(cap_prot->payload + cap_prot->payload_size);
            char* script_tag = (char*)(cap_prot->payload + cap_prot->payload_size + 4);
            char* query_var_value = __url_query_value(&iter_copy, query_var_name, &buffer[0]);
            if(likely(!query_var_value)) {
                char str[14]; str[0]='v'; str[1]='a'; str[2]='r'; str[3]=' '; str[4]='n'; str[5]='o'; str[6]='t'; str[7]=' '; str[8]='f'; str[9]='o'; str[10]='u'; str[11]='n'; str[12]='d'; str[13]=0;
                print_num(str, 0);
                return false;
            }
            return bpf_strstr(query_var_value, script_tag) != NULL;
        }
    }

    // No matches found
    return false;
 }
