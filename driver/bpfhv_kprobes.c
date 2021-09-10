#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/preempt.h>
#include <net/sock.h>
#include "types.h"
#include "bpfhv_kprobes.h"
#include "bpfhv_ids_flow.h"
#include "bpfhv_progs_registry.h"
#include "log.h"


/*#define sched_preempt_enable_no_resched() \
    do { \
    	barrier(); \
    	preempt_count_dec(); \
    } while (0)
#define preempt_enable_no_resched() sched_preempt_enable_no_resched()*/



/*
 * Function prototypes
 */
bool bpfhv_prog_is_present(struct bpfhv_info* bi, const uint32_t index);
uint32_t run_bpfhv_prog_1(struct bpfhv_info* bi, const uint32_t index, void* arg);

/*
 * Macros
 */
#define reset_current_kprobe() \
    __this_cpu_write(p, NULL);


#ifdef IDS

static struct kprobe kp_inet_recvmsg = {
	.symbol_name	= "inet_recvmsg",
};

static struct kprobe kp_inet_release = {
	.symbol_name	= "inet_release",
};

/**
 * kprobe pre_handler: called just before the probed instruction is executed.
 * probed function ->
 *     int inet_recvmsg(struct socket *sock, struct msghdr *msg, size_t size, int flags);
 * This pre_handler aims to replace inet_recvmsg(...) with inet_recvmsg_replacement(...).
 */
static int
__kp_inet_recvmsg_pre_handler(struct kprobe *p, struct pt_regs *regs) {
    regs->ip = (uintptr_t)inet_recvmsg_replacement;
    reset_current_kprobe();
    return 1;
}


/*
 * fault_handler: this is called if an exception is generated for any instruction within the pre-
 * or post-handler, or when Kprobes single-steps the probed instruction.
 */
static int
__kp_null_fault_handler(struct kprobe *p, struct pt_regs *regs, int trapnr) {
	printk(
		KERN_ERR "__kp_null_fault_handler: p->addr = 0x%p, trap #%dn",
		p->addr, trapnr
	);
	// Return 0 because we don't handle the fault
	return 0;
}


/**
 * kprobe pre_handler: called just before the probed instruction is executed.
 * probed function ->
 *     int inet_release(struct socket *sock)
 * This pre_handler aims to replace inet_release(...).
 */
static int
__kp_inet_release_pre_handler(struct kprobe *p, struct pt_regs *regs) {
    struct sock* sk;
    struct socket* socket;
    struct bpfhv_info* owner_bpfhv_info;
    struct flow_id flow_id;

    socket = (struct socket*)(uintptr_t)regs->di;
    if(unlikely(!socket)) {
        return 0;
    }
    sk = socket->sk;
    if(unlikely(!sk)) {
        return 0;
    }

    // Compute flow_id related to sk
    if(unlikely(!server_sock_to_flow_id(sk, &flow_id))) {
        return 0;
    }

    // Check if the flow exists and if it is releated to some BPF program (called the "owner")
    owner_bpfhv_info = get_flow_owner(&flow_id);
    if(likely(!owner_bpfhv_info)) {
        return 0;
    }

    // If I am here there is an owner and it must be reported that the socket is being released,
    // but if the owner has no BPFHV_PROG_SOCKET_RELEASED programs we can avoid this step.
    if(unlikely(bpfhv_prog_is_present(owner_bpfhv_info, BPFHV_PROG_SOCKET_RELEASED))) {
        run_bpfhv_prog_1(owner_bpfhv_info, BPFHV_PROG_SOCKET_RELEASED, &flow_id);
    }

    return 0;
}

#endif


/**
 * Doc in bpfhv_kprobes.h
 */
bool
bpfhv_kprobes_ini(void) {
    #ifdef IDS

    int ret;

    kp_inet_recvmsg.pre_handler = __kp_inet_recvmsg_pre_handler;
    kp_inet_recvmsg.fault_handler = __kp_null_fault_handler;
    kp_inet_release.pre_handler = __kp_inet_release_pre_handler;
    kp_inet_release.fault_handler = __kp_null_fault_handler;

    ret = register_kprobe(&kp_inet_recvmsg);
    if(ret < 0) {
        printk(KERN_ERR "register_kprobe kp_inet_recvmsg failed, returned %d\n", ret);
        return false;
    }

    ret = register_kprobe(&kp_inet_release);
    if(ret < 0) {
        printk(KERN_ERR "register_kprobe kp_inet_release failed, returned %d\n", ret);
        return false;
    }

    print_debug("kprobes registered successfully\n");

    #endif

    return true;
}

/**
 * Doc in bpfhv_kprobes.h
 */
void
bpfhv_kprobes_fini(void) {
    #ifdef IDS
    unregister_kprobe(&kp_inet_recvmsg);
    unregister_kprobe(&kp_inet_release);
    #endif
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Federico Cappellini");
