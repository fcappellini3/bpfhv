/**
 * Basic example of pdt memory. This is the one used for performance evaluation.
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
            .payload_size = 5,
            .payload = {'H', 'T', 'T', 'P', '/'},
            .action = CAPTURE
        }/*,
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
        }*/
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
