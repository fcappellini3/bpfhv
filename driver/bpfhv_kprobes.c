#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/preempt.h>
#include <net/sock.h>
#include "types.h"
#include "bpfhv_kprobes.h"
#include "bpfhv_ids_flow.h"


/*#define sched_preempt_enable_no_resched() \
    do { \
    	barrier(); \
    	preempt_count_dec(); \
    } while (0)
#define preempt_enable_no_resched() sched_preempt_enable_no_resched()*/

#define reset_current_kprobe() \
    __this_cpu_write(p, NULL);


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
    //struct socket* socket = (struct socket*)(uintptr_t)regs->di;
    //struct sock *sk = socket->sk;
    //printk(KERN_ERR "__kp_inet_release_pre_handler(...) called -> %lx\n", (uintptr_t)sk);
    return 0;
}


/**
 * Doc in bpfhv_kprobes.h
 */
bool
bpfhv_kprobes_ini(void) {
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

    return true;
}

/**
 * Doc in bpfhv_kprobes.h
 */
void
bpfhv_kprobes_fini(void) {
    unregister_kprobe(&kp_inet_recvmsg);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Federico Cappellini");







/**
 * kprobe post_handler: called after the probed instruction is executed
 * probed function ->
 *     int inet_recvmsg(struct socket *sock, struct msghdr *msg, size_t size, int flags);
 * TO DEBUG:
 * printk(
 *     KERN_ERR "__kp_inet_recvmsg_post_handler: p->addr = 0x%p, flags = 0x%lx\n",
 *     p->addr, regs->flags
 * );
 */
/*static void
__kp_inet_recvmsg_post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags) {

}*/
