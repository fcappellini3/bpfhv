#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <assert.h>
#include <poll.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <stdlib.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <signal.h>
#ifdef WITH_NETMAP
#include <libnetmap.h>
#endif
#include <linux/if.h>

#include "backend.h"

#ifdef PROXY_IDS
#include "proxy_ids/proxy_ids.h"
#endif

int verbose = 0;

#define RXI_BEGIN(_s)   0
#define RXI_END(_s)     (_s)->num_queue_pairs
#define TXI_BEGIN(_s)   (_s)->num_queue_pairs
#define TXI_END(_s)     (_s)->num_queues
#define SET_ALL_BES(WHAT, VALUE) for(i = 0; i < bes_size; ++i) bes[i].WHAT = VALUE
#define ALL_BES for(i = 0; i < bes_size; ++i) bes[i]
#define MAX_BES_SIZE 128
#define GET_READY_BACKEND_FAIL (void*)(uintptr_t)(uint64_t)0xFFFFFFFFFFFFFFFFULL

#define OPT_TXCSUM      (1 << 0)
#define OPT_RXCSUM      (1 << 1)
#define OPT_TSO         (1 << 2)
#define OPT_LRO         (1 << 3)

/* Main data structure. */
#ifdef MULTI_BACKEND
static BpfhvBackend* bes;
static uint32_t bes_size;
#else
static BpfhvBackend be;
#endif

/* Helper functions to signal and drain eventfds. */
static inline void
eventfd_drain(int fd)
{
    uint64_t x = 123;
    int n;

    n = read(fd, &x, sizeof(x));
    if (unlikely(n != sizeof(x))) {
        assert(n < 0);
        fprintf(stderr, "read() failed: %s\n", strerror(errno));
    }
}

static inline void
eventfd_signal(int fd)
{
    uint64_t x = 1;
    int n;

    n = write(fd, &x, sizeof(x));
    if (unlikely(n != sizeof(x))) {
        assert(n < 0);
        fprintf(stderr, "read() failed: %s\n", strerror(errno));
    }
}

static ssize_t
tap_recv(BpfhvBackend *be, const struct iovec *iov, size_t iovcnt)
{
    return readv(be->befd, iov, iovcnt);
}

static ssize_t
tap_send(BpfhvBackend *be, const struct iovec *iov, size_t iovcnt)
{
    return writev(be->befd, iov, iovcnt);
}

static ssize_t
sink_send(BpfhvBackend *be, const struct iovec *iov, size_t iovcnt)
{
    ssize_t bytes = 0;
    unsigned int i;

    for (i = 0; i < iovcnt; i++, iov++) {
        bytes += iov->iov_len;
    }

    return bytes;
}

static ssize_t
null_recv(BpfhvBackend *be, const struct iovec *iov, size_t iovcnt)
{
    return 0;  /* Nothing to read. */
}

static ssize_t
source_recv(BpfhvBackend *be, const struct iovec *iov, size_t iovcnt)
{
    static const uint8_t udp_pkt[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x10,
        0x00, 0x2e, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x26, 0xad, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x01,
        0x00, 0x01, 0x04, 0xd2, 0x04, 0xd2, 0x00, 0x1a, 0x15, 0x80, 0x6e, 0x65, 0x74, 0x6d, 0x61, 0x70,
        0x20, 0x70, 0x6b, 0x74, 0x2d, 0x67, 0x65, 0x6e, 0x20, 0x44, 0x49, 0x52,
    };
    unsigned int i = 0;
    size_t ofs = 0;

    if (be->vnet_hdr_len) {
        assert(iov->iov_len == sizeof(struct virtio_net_hdr_v1));
        memset(iov->iov_base, 0, iov->iov_len);
        iov++;
        i++;
    }

    for (; i < iovcnt && ofs < sizeof(udp_pkt); i++, iov++) {
        size_t copy = sizeof(udp_pkt) - ofs;

        if (copy > iov->iov_len) {
            copy = iov->iov_len;
        }
        memcpy(iov->iov_base, udp_pkt + ofs, copy);
        ofs += copy;
    }

    return ofs;
}

#ifdef WITH_NETMAP
static ssize_t
netmap_recv(BpfhvBackend *be, const struct iovec *iov, size_t iovcnt)
{
    struct netmap_ring *ring = be->nm.rxr;
    uint32_t head = ring->head;
    uint32_t tail = ring->tail;
    struct netmap_slot *slot;
    size_t iov_frag_left;
    size_t nm_frag_left;
    size_t iov_frag_ofs;
    size_t nm_frag_ofs;
    ssize_t totlen = 0;
    uint8_t *src;

    if (unlikely(head == tail)) {
        /* Nothing to read. */
        return 0;
    }

    iov_frag_left = iov->iov_len;
    iov_frag_ofs = 0;
    slot = ring->slot + head;
    src = (uint8_t *)NETMAP_BUF(ring, slot->buf_idx);
    nm_frag_left = slot->len;
    nm_frag_ofs = 0;

    for (;;) {
        size_t copy;

        copy = MIN(nm_frag_left, iov_frag_left);
        memcpy(iov->iov_base + iov_frag_ofs, src + nm_frag_ofs, copy);
        iov_frag_ofs += copy;
        iov_frag_left -= copy;
        nm_frag_ofs += copy;
        nm_frag_left -= copy;
        totlen += copy;

        if (nm_frag_left == 0) {
            head = nm_ring_next(ring, head);
            if ((slot->flags & NS_MOREFRAG) == 0 || head == tail) {
                /* End Of Packet (or truncated packet). */
                break;
            }
            slot = ring->slot + head;
            src = (uint8_t *)NETMAP_BUF(ring, slot->buf_idx);
            nm_frag_left = slot->len;
            nm_frag_ofs = 0;
        }

        if (iov_frag_left == 0) {
            iovcnt--;
            if (iovcnt == 0) {
                size_t truncated = nm_frag_left;

                /* Ran out of space in the iovec. Skip the rest
                 * of the packet. */
                while ((slot->flags & NS_MOREFRAG) && head != tail) {
                    head = nm_ring_next(ring, head);
                    slot = ring->slot + head;
                    truncated += slot->len;
                }
                fprintf(stderr, "Not enough space in the recv iovec "
                                "(%zu bytes truncated)\n", truncated);
                break;
            }
            iov++;
            iov_frag_left = iov->iov_len;
            iov_frag_ofs = 0;
        }
    }

    ring->head = ring->cur = head;

    return totlen;
}

static ssize_t
netmap_send(BpfhvBackend *be, const struct iovec *iov, size_t iovcnt)
{
    struct netmap_ring *ring = be->nm.txr;
    uint32_t head = ring->head;
    uint32_t tail = ring->tail;
    struct netmap_slot *slot;
    size_t iov_frag_left;
    size_t nm_frag_left;
    size_t iov_frag_ofs;
    size_t nm_frag_ofs;
    ssize_t totlen = 0;
    uint8_t *dst;

    iov_frag_left = iov->iov_len;
    iov_frag_ofs = 0;
    slot = ring->slot + head;
    dst = (uint8_t *)NETMAP_BUF(ring, slot->buf_idx);
    nm_frag_left = ring->nr_buf_size;
    nm_frag_ofs = 0;

    for (;;) {
        size_t copy;

        if (unlikely(head == tail)) {
            /* Ran out of descriptors. */
            ring->cur = tail;
            return 0;
        }

        copy = MIN(nm_frag_left, iov_frag_left);
        memcpy(dst + nm_frag_ofs, iov->iov_base + iov_frag_ofs, copy);
        iov_frag_ofs += copy;
        iov_frag_left -= copy;
        nm_frag_ofs += copy;
        nm_frag_left -= copy;
        totlen += copy;

        if (iov_frag_left == 0) {
            iovcnt--;
            if (iovcnt == 0) {
                break;
            }
            iov++;
            iov_frag_left = iov->iov_len;
            iov_frag_ofs = 0;
        }

        if (nm_frag_left == 0) {
            slot->len = nm_frag_ofs;
            slot->flags = NS_MOREFRAG;
            head = nm_ring_next(ring, head);
            slot = ring->slot + head;
            dst = (uint8_t *)NETMAP_BUF(ring, slot->buf_idx);
            nm_frag_left = ring->nr_buf_size;
            nm_frag_ofs = 0;
        }
    }

    slot->len = nm_frag_ofs;
    slot->flags = 0;
    head = nm_ring_next(ring, head);
    ring->head = ring->cur = head;

    return totlen;
}

static void
netmap_sync(BpfhvBackend *be)
{
    /* Optimization: use poll() with 0 timeout to perform the equivalent
     * of ioctl(NIOCTXSYNC) + ioctl(NIOCRXSYNC) with a single system call. */
    struct pollfd pfd = {
        .fd = be->befd,
        .events = POLLIN | POLLOUT,
    };
    poll(&pfd, 1, /*timeout_ms=*/0);
}
#endif

static void
process_packets_poll(BpfhvBackend *be)
{
    BeOps ops = be->ops;
    int very_verbose = (verbose >= 2);
    int sleep_usecs = be->sleep_usecs;
    struct pollfd *pfd_stop;
    struct pollfd *pfd_if;
    int poll_timeout = -1;
    struct pollfd *pfd;
    unsigned int nfds;
    int can_receive;
    unsigned int i;
    int can_send;

    nfds = be->num_queues + 2;
    pfd = calloc(nfds, sizeof(pfd[0]));
    assert(pfd != NULL);
    pfd_if = pfd + nfds - 2;
    pfd_stop = pfd + nfds - 1;

    for (i = 0; i < be->num_queues; i++) {
        pfd[i].fd = be->q[i].kickfd;
        pfd[i].events = POLLIN;
    }
    pfd_if->fd = be->befd;
    pfd_if->events = 0;
    pfd_stop->fd = be->stopfd;
    pfd_stop->events = POLLIN;
    can_receive = can_send = 1;

    /* Start with guest-->host notifications enabled. */
    for (i = RXI_BEGIN(be); i < RXI_END(be); i++) {
        ops.rxq_kicks(be->q[i].ctx.rx, /*enable=*/1);
    }
    for (i = TXI_BEGIN(be); i < TXI_END(be); i++) {
        ops.txq_kicks(be->q[i].ctx.tx, /*enable=*/1);
    }

    /* Only single-queue is support for now. */
    assert(be->num_queue_pairs == 1);

    for (;;) {
        int n;

        /* Poll TAP interface for new receive packets only if we
         * can actually receive packets. If TAP send buffer is full we
         * also wait on more room. */
        pfd_if->events = can_receive ? POLLIN : 0;
        if (unlikely(!can_send)) {
            pfd_if->events |= POLLOUT;
        }

        n = poll(pfd, nfds, poll_timeout);
        if (unlikely(n < 0)) {
            fprintf(stderr, "poll() failed: %s\n", strerror(errno));
            break;
        }
        poll_timeout = -1;

        /* Drain transmit and receive kickfds if needed. */
        for (i = 0; i < be->num_queues; i++) {
            if (pfd[i].revents & POLLIN) {
                be->q[i].stats.kicks++;
                if (unlikely(very_verbose)) {
                    printf("Kick on %s\n", be->q[i].name);
                }
                eventfd_drain(pfd[i].fd);
            }
        }

        /* Receive any packets from the TAP interface and push them to
         * the first (and unique) RXQ. */
        {
            BpfhvBackendQueue *rxq = be->q + 0;
            size_t count;

            can_receive = 1;
            count = ops.rxq_push(be, rxq, &can_receive);
            if (rxq->notify) {
                rxq->stats.irqs++;
                eventfd_signal(rxq->irqfd);
                if (unlikely(very_verbose)) {
                    printf("Interrupt on %s\n", rxq->name);
                }
            }
            if (count >= BPFHV_BE_RX_BUDGET) {
                /* Out of budget. Make sure next poll() does not block,
                 * so that we can keep processing. */
                poll_timeout = 0;
            }
            if (unlikely(very_verbose && count > 0)) {
                ops.rxq_dump(rxq->ctx.rx);
            }
        }

        /* Drain any packets from the transmit queues. */
        for (i = TXI_BEGIN(be); i < TXI_END(be); i++) {
            BpfhvBackendQueue *txq = be->q + i;
            struct bpfhv_tx_context *ctx = txq->ctx.tx;
            size_t count;

            can_send = 1;
            count = ops.txq_drain(be, txq, &can_send);
            if (txq->notify) {
                txq->stats.irqs++;
                eventfd_signal(txq->irqfd);
                if (unlikely(very_verbose)) {
                    printf("Interrupt on %s\n", txq->name);
                }
            }
            if (count >= BPFHV_BE_TX_BUDGET) {
                /* Out of budget. Make sure next poll() does not block,
                 * so that we can keep processing in the next iteration. */
                poll_timeout = 0;
            }
            if (unlikely(very_verbose && count > 0)) {
                ops.txq_dump(ctx);
            }
        }

        /* Check if we need to stop. */
        if (unlikely(pfd_stop->revents & POLLIN)) {
            eventfd_drain(pfd_stop->fd);
            if (verbose) {
                printf("Thread stopped\n");
            }
            break;
        }

        if (sleep_usecs > 0) {
            usleep(sleep_usecs);
        }
    }

    free(pfd);
}

static void
process_packets_spin(BpfhvBackend *be)
{
    BeOps ops = be->ops;
    int very_verbose = (verbose >= 2);
    int sleep_usecs = be->sleep_usecs;
    unsigned int i;

    /* Disable all guest-->host notifications. */
    for (i = RXI_BEGIN(be); i < RXI_END(be); i++) {
        ops.rxq_kicks(be->q[i].ctx.rx, /*enable=*/0);
    }
    for (i = TXI_BEGIN(be); i < TXI_END(be); i++) {
        ops.txq_kicks(be->q[i].ctx.tx, /*enable=*/0);
    }

    while (ACCESS_ONCE(be->stopflag) == 0) {
        if (be->sync) {
            be->sync(be);
        }

        /* Read packets from the backend interface (e.g. TAP, netmap)
         * into the first receive queue. */
        {
            BpfhvBackendQueue *rxq = be->q + 0;
            size_t count;

            count = ops.rxq_push(be, rxq, /*can_receive=*/NULL);
            if (rxq->notify) {
                rxq->stats.irqs++;
                eventfd_signal(rxq->irqfd);
                if (unlikely(very_verbose)) {
                    printf("Interrupt on %s\n", rxq->name);
                }
            }
            if (unlikely(very_verbose && count > 0)) {
                ops.rxq_dump(rxq->ctx.rx);
            }
        }

        /* Drain the packets from the transmit queues, sending them
         * to the backend interface. */
        for (i = TXI_BEGIN(be); i < TXI_END(be); i++) {
            BpfhvBackendQueue *txq = be->q + i;
            size_t count;

            count = ops.txq_drain(be, txq, /*can_send=*/NULL);
            if (txq->notify) {
                txq->stats.irqs++;
                eventfd_signal(txq->irqfd);
                if (unlikely(very_verbose)) {
                    printf("Interrupt on %s\n", txq->name);
                }
            }
            if (unlikely(very_verbose && count > 0)) {
                ops.txq_dump(txq->ctx.tx);
            }
        }
        if (sleep_usecs > 0) {
            usleep(sleep_usecs);
        }
    }
}

static void *
process_packets(void *opaque)
{
    BpfhvBackend *be = opaque;

    if (verbose) {
        printf("Thread started\n");
    }

    if (be->busy_wait) {
        process_packets_spin(be);
    } else {
        process_packets_poll(be);
    }

    return NULL;
}

/* Helper function to validate the number of buffers. */
static int
num_bufs_valid(uint64_t num_bufs)
{
    if (num_bufs < 16 || num_bufs > 8192 ||
            (num_bufs & (num_bufs - 1)) != 0) {
        return 0;
    }
    return 1;
}

/* Is the backend ready to process packets ? */
static int
backend_ready(BpfhvBackend *be)
{
    int i;

    for (i = 0; i < be->num_queues; i++) {
        if (be->q[i].ctx.rx == NULL) {
            return 0;
        }

        if (be->q[i].kickfd < 0) {
            return 0;
        }

        if (be->q[i].irqfd < 0) {
            return 0;
        }
    }

    return be->num_queue_pairs > 0 && num_bufs_valid(be->num_rx_bufs) &&
           num_bufs_valid(be->num_tx_bufs) && be->num_regions > 0;
}

static void
backend_drain(BpfhvBackend *be)
{
    unsigned int i;

    /* Drain any pending transmit buffers. */
    for (i = TXI_BEGIN(be); i < TXI_END(be); i++) {
        BpfhvBackendQueue *txq = be->q + i;
        size_t drained = 0;

        for (;;) {
            size_t count;

            count = be->ops.txq_drain(be, txq, /*can_send=*/NULL);
            drained += count;
            if (drained >= be->num_tx_bufs || count == 0) {
                break;
            }
        }
        if (verbose && drained > 0) {
            printf("Drained %zu packets from %s\n", drained, txq->name);
        }
    }
}

/* Helper function to stop the packet processing thread and join it. */
static int
backend_stop(BpfhvBackend *be)
{
    int ret;

    eventfd_signal(be->stopfd);
    ACCESS_ONCE(be->stopflag) = 1;
    __atomic_thread_fence(__ATOMIC_RELEASE);
    ret = pthread_join(be->th, NULL);
    if (ret) {
        fprintf(stderr, "pthread_join() failed: %s\n",
                strerror(ret));
        return ret;
    }
    be->running = 0;

    return 0;
}

static void
stats_show(BpfhvBackend *be)
{
    struct timeval t;
    unsigned long udiff;
    double mdiff;
    unsigned int i;

    gettimeofday(&t, NULL);
    udiff = (t.tv_sec - be->stats_ts.tv_sec) * 1000000 +
            (t.tv_usec - be->stats_ts.tv_usec);
    mdiff = udiff / 1000.0;

    printf("Statistics:\n");
    for (i = 0; i < be->num_queues; i++) {
        BpfhvBackendQueue *q = be->q + i;
        double dbufs = ACCESS_ONCE(q->stats.bufs) - q->pstats.bufs;
        double dpkts = ACCESS_ONCE(q->stats.pkts) - q->pstats.pkts;
        double dbatches = ACCESS_ONCE(q->stats.batches) - q->pstats.batches;
        double dkicks = ACCESS_ONCE(q->stats.kicks) - q->pstats.kicks;
        double dirqs = ACCESS_ONCE(q->stats.irqs) - q->pstats.irqs;
        double pkt_batch = 0.0;
        double buf_batch = 0.0;

        q->pstats = q->stats;
        dbufs /= mdiff;
        dpkts /= mdiff;
        dbatches /= mdiff;
        dkicks /= mdiff;
        dirqs /= mdiff;
        if (dbatches) {
            pkt_batch = dpkts / dbatches;
            buf_batch = dbufs / dbatches;
        }
        printf("    %s: %4.3f Kpps, %4.3f Kkicks/s, %4.3f Kirqs/s, "
               " pkt_batch %3.1f buf_batch %3.1f\n",
               q->name, dpkts, dkicks, dirqs, pkt_batch, buf_batch);
    }

    be->stats_ts = t;
}

static int
tap_alloc(const char *ifname, int vnet_hdr_len, int opt_offload)
{
    unsigned int offloads = 0;
    struct ifreq ifr;
    int fd, err;

    if (ifname == NULL) {
        fprintf(stderr, "Missing tap ifname\n");
        return -1;
    }

    /* Open the clone device. */
    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "open(/dev/net/tun) failed: %s\n",
                strerror(errno));
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));
    /* IFF_TAP, IFF_TUN, IFF_NO_PI, IFF_VNET_HDR */
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if (opt_offload) {
        ifr.ifr_flags |= IFF_VNET_HDR;
    }
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ-1] = '\0';

    /* Try to create the device. */
    err = ioctl(fd, TUNSETIFF, (void *)&ifr);
    if(err < 0) {
        fprintf(stderr, "ioctl(befd, TUNSETIFF) failed: %s\n",
                strerror(errno));
        close(fd);
        return err;
    }

    if (opt_offload) {
        err = ioctl(fd, TUNSETVNETHDRSZ, &vnet_hdr_len);
        if (err < 0) {
            fprintf(stderr, "ioctl(befd, TUNSETIFF) failed: %s\n",
                    strerror(errno));
        }

        if (opt_offload & OPT_RXCSUM) {
            offloads |= TUN_F_CSUM;
            if (opt_offload & OPT_LRO) {
                offloads |= TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_UFO;
            }
        }
    }

    err = ioctl(fd, TUNSETOFFLOAD, offloads);
    if (err < 0) {
        fprintf(stderr, "ioctl(befd, TUNSETOFFLOAD) failed: %s\n",
                strerror(errno));
    }

    return fd;
}

static void
check_alignments(void)
{
    sring_ops.rx_check_alignment();
    sring_ops.tx_check_alignment();
    sring_gso_ops.rx_check_alignment();
    sring_gso_ops.tx_check_alignment();
    vring_packed_ops.rx_check_alignment();
    vring_packed_ops.tx_check_alignment();
}

static void
usage(const char *progname)
{
    printf("%s:\n"
           "    -h (show this help and exit)\n"
           "    -p UNIX_SOCKET_PATH\n"
           "    -P PID_FILE\n"
           "    -i INTERFACE_NAME\n"
           "    -b BACKEND_TYPE (tap,sink,source,netmap)\n"
           "    -d DEVICE_TYPE (sring,sring_gso,vring_packed)\n"
           "    -O OFFLOAD (txcsum,rxcsum,tso,lro)\n"
           "    -C (enable TX/RX checksum offloads)\n"
           "    -G (enable TCP/UDP GSO offloads)\n"
           "    -B (run in busy-wait mode)\n"
           "    -S (show run-time statistics)\n"
           "    -u MICROSECONDS (per iteration sleep)\n"
           "    -v (increase verbosity level)\n",
            progname);
}

#ifndef MULTI_BACKEND
static void
sigint_handler(int signum)
{
    if (be.running) {
        if (verbose) {
            printf("Running backend interrupted\n");
        }
        backend_stop(&be);
        backend_drain(&be);
    }
    if (be.pidfile != NULL) {
        unlink(be.pidfile);
    }
    exit(EXIT_SUCCESS);
}

/* Control loop to process requests coming from the hypervisor. */
static int
main_loop(BpfhvBackend *be)
{
    int poll_timeout;
    int ret = -1;
    int i;

    be->features_sel = 0;
    be->num_queue_pairs = be->num_queues = 0;
    be->num_rx_bufs = 0;
    be->num_tx_bufs = 0;
    be->running = 0;
    be->status = 0;
    be->upgrade_fd = -1;

    for (i = 0; i < BPFHV_MAX_QUEUES; i++) {
        be->q[i].ctx.rx = NULL;
        be->q[i].kickfd = be->q[i].irqfd = -1;
    }

    be->stopfd = eventfd(0, 0);
    if (be->stopfd < 0) {
        fprintf(stderr, "eventfd() failed: %s\n", strerror(errno));
        return -1;
    }
    be->stopflag = 0;

    ret = fcntl(be->stopfd, F_SETFL, O_NONBLOCK);
    if (ret) {
        fprintf(stderr, "fcntl(stopfd, F_SETFL) failed: %s\n",
                strerror(errno));
        return -1;
    }

    ret = fcntl(be->befd, F_SETFL, O_NONBLOCK);
    if (ret) {
        fprintf(stderr, "fcntl(befd, F_SETFL) failed: %s\n",
                strerror(errno));
        return -1;
    }

    poll_timeout = be->collect_stats ? 2000/*ms*/ : -1;
    gettimeofday(&be->stats_ts, NULL);

    for (;;) {
        ssize_t payload_size = 0;
        BpfhvProxyMessage resp = { };

        /* Variables to store recvmsg() ancillary data. */
        int fds[BPFHV_PROXY_MAX_REGIONS] = { };
        size_t num_fds = 0;

        /* Variables to store sendmsg() ancillary data. */
        int outfds[BPFHV_PROXY_MAX_REGIONS] = { };
        size_t num_outfds = 0;

        /* Support variables for reading a bpfhv-proxy message header. */
        char control[CMSG_SPACE(BPFHV_PROXY_MAX_REGIONS * sizeof(fds[0]))] = {};
        BpfhvProxyMessage msg = { };
        struct iovec iov = {
            .iov_base = &msg.hdr,
            .iov_len = sizeof(msg.hdr),
        };
        struct msghdr mh = {
            .msg_iov = &iov,
            .msg_iovlen = 1,
            .msg_control = control,
            .msg_controllen = sizeof(control),
        };
        struct cmsghdr *cmsg;
        ssize_t n;

        /* Wait for the next message to arrive. */
        struct pollfd pfd[1];

        pfd[0].fd = be->cfd;
        pfd[0].events = POLLIN;
        n = poll(pfd, sizeof(pfd)/sizeof(pfd[0]), poll_timeout);
        if (n == 0) {
            /* Timeout. We need to compute and show statistics. */
            if (be->running) {
                stats_show(be);
            }
            continue;
        } else if (n < 0) {
            fprintf(stderr, "poll() failed: %s\n", strerror(errno));
            break;
        }

        /* Read a bpfhv-proxy message header plus ancillary data. */
        do {
            n = recvmsg(be->cfd, &mh, 0);
        } while (n < 0 && (errno == EINTR || errno == EAGAIN));
        if (n < 0) {
            fprintf(stderr, "recvmsg(cfd) failed: %s\n", strerror(errno));
            break;
        }

        if (n == 0) {
            /* EOF */
            if (verbose) {
                printf("Connection closed by the hypervisor\n");
            }
            break;
        }

        /* Scan ancillary data looking for file descriptors. */
        for (cmsg = CMSG_FIRSTHDR(&mh); cmsg != NULL;
                cmsg = CMSG_NXTHDR(&mh, cmsg)) {
            if (cmsg->cmsg_level == SOL_SOCKET &&
                    cmsg->cmsg_type == SCM_RIGHTS) {
                size_t arr_size = cmsg->cmsg_len - CMSG_LEN(0);

                num_fds = arr_size / sizeof(fds[0]);
                if (num_fds > BPFHV_PROXY_MAX_REGIONS) {
                    fprintf(stderr, "Message contains too much ancillary data "
                            "(%zu file descriptors)\n", num_fds);
                    return -1;
                }
                memcpy(fds, CMSG_DATA(cmsg), arr_size);

                break; /* Discard any other ancillary data. */
            }
        }

        if (n < (ssize_t)sizeof(msg.hdr)) {
            fprintf(stderr, "Message too short (%zd bytes)\n", n);
            break;
        }

        if ((msg.hdr.flags & BPFHV_PROXY_F_VERSION_MASK)
                != BPFHV_PROXY_VERSION) {
            fprintf(stderr, "Protocol version mismatch: expected %u, got %u",
                    BPFHV_PROXY_VERSION,
                    msg.hdr.flags & BPFHV_PROXY_F_VERSION_MASK);
            break;
        }

        /* Check that payload size is correct. */
        switch (msg.hdr.reqtype) {
        case BPFHV_PROXY_REQ_GET_FEATURES:
        case BPFHV_PROXY_REQ_GET_PROGRAMS:
        case BPFHV_PROXY_REQ_RX_ENABLE:
        case BPFHV_PROXY_REQ_TX_ENABLE:
        case BPFHV_PROXY_REQ_RX_DISABLE:
        case BPFHV_PROXY_REQ_TX_DISABLE:
            payload_size = 0;
            break;

        case BPFHV_PROXY_REQ_SET_FEATURES:
            payload_size = sizeof(msg.payload.u64);
            break;

        case BPFHV_PROXY_REQ_SET_PARAMETERS:
            payload_size = sizeof(msg.payload.params);
            break;

        case BPFHV_PROXY_REQ_SET_MEM_TABLE:
            payload_size = sizeof(msg.payload.memory_map);
            break;

        case BPFHV_PROXY_REQ_SET_QUEUE_CTX:
            payload_size = sizeof(msg.payload.queue_ctx);
            break;

        case BPFHV_PROXY_REQ_SET_QUEUE_KICK:
        case BPFHV_PROXY_REQ_SET_QUEUE_IRQ:
        case BPFHV_PROXY_REQ_SET_UPGRADE:
            payload_size = sizeof(msg.payload.notify);
            break;

        default:
            fprintf(stderr, "Invalid request type (%d)\n", msg.hdr.reqtype);
            return -1;
        }

        if (payload_size != msg.hdr.size) {
            fprintf(stderr, "Payload size mismatch: expected %zd, got %u\n",
                    payload_size, msg.hdr.size);
            break;
        }

        /* Read payload. */
        do {
            n = read(be->cfd, &msg.payload, payload_size);
        } while (n < 0 && (errno == EINTR || errno == EAGAIN));
        if (n < 0) {
            fprintf(stderr, "read(cfd, payload) failed: %s\n",
                    strerror(errno));
            break;
        }

        if (n != payload_size) {
            fprintf(stderr, "Truncated payload: expected %zd bytes, "
                    "but only %zd were read\n", payload_size, n);
            break;
        }

        resp.hdr.reqtype = msg.hdr.reqtype;
        resp.hdr.flags = BPFHV_PROXY_VERSION;

        /* Check if this request is acceptable while the backend
         * is running. */
        switch (msg.hdr.reqtype) {
        case BPFHV_PROXY_REQ_SET_FEATURES:
        case BPFHV_PROXY_REQ_SET_PARAMETERS:
        case BPFHV_PROXY_REQ_SET_QUEUE_CTX:
        case BPFHV_PROXY_REQ_SET_QUEUE_KICK:
            if (be->running) {
                fprintf(stderr, "Cannot accept request because backend "
                                "is running\n");
                resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
                goto send_resp;
            }
            break;
        default:
            break;
        }

        /* Process the request. */
        switch (msg.hdr.reqtype) {
        case BPFHV_PROXY_REQ_SET_FEATURES:
            be->features_sel = be->features_avail & msg.payload.u64;
            if (verbose) {
                printf("Negotiated features %"PRIx64"\n", be->features_sel);
            }
            if (be->features_sel &
                    (BPFHV_F_TCPv4_LRO | BPFHV_F_TCPv6_LRO | BPFHV_F_UDP_LRO)) {
                be->max_rx_pkt_size = 65536;
            } else {
                be->max_rx_pkt_size = 1518;
            }
            /* TODO We should also set be->vnet_hdr_len here ... */

            break;

        case BPFHV_PROXY_REQ_GET_FEATURES:
            resp.hdr.size = sizeof(resp.payload.u64);
            resp.payload.u64 = be->features_avail;
            break;

        case BPFHV_PROXY_REQ_SET_PARAMETERS: {
            BpfhvProxyParameters *params = &msg.payload.params;

            if (params->num_rx_queues != 1 || params->num_tx_queues != 1) {
                resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
            } else if (!num_bufs_valid(params->num_rx_bufs) ||
                       !num_bufs_valid(params->num_tx_bufs)) {
                resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
            } else {
                unsigned int i;

                be->num_queue_pairs = (unsigned int)params->num_rx_queues;
                be->num_rx_bufs = (unsigned int)params->num_rx_bufs;
                be->num_tx_bufs = (unsigned int)params->num_tx_bufs;
                if (verbose) {
                    printf("Set queue parameters: %u queue pairs, %u rx bufs, "
                          "%u tx bufs\n", be->num_queue_pairs,
                           be->num_rx_bufs, be->num_tx_bufs);
                }

                be->num_queues = 2 * be->num_queue_pairs;

                resp.hdr.size = sizeof(resp.payload.ctx_sizes);
                resp.payload.ctx_sizes.rx_ctx_size =
                    be->ops.rx_ctx_size(be->num_rx_bufs);
                resp.payload.ctx_sizes.tx_ctx_size =
                    be->ops.tx_ctx_size(be->num_tx_bufs);

                for (i = RXI_BEGIN(be); i < RXI_END(be); i++) {
                    snprintf(be->q[i].name, sizeof(be->q[i].name),
                             "RX%u", i);
                }
                for (i = TXI_BEGIN(be); i < TXI_END(be); i++) {
                    snprintf(be->q[i].name, sizeof(be->q[i].name),
                             "TX%u", i-be->num_queue_pairs);
                }
            }
            break;
        }

        case BPFHV_PROXY_REQ_SET_MEM_TABLE: {
            BpfhvProxyMemoryMap *map = &msg.payload.memory_map;
            size_t i;

            /* Perform sanity checks. */
            if (map->num_regions > BPFHV_PROXY_MAX_REGIONS) {
                resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
                fprintf(stderr, "Too many memory regions: %u\n",
                        map->num_regions);
                return -1;
            }
            if (num_fds != map->num_regions) {
                resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
                fprintf(stderr, "Mismatch between number of regions (%u) and "
                        "number of file descriptors (%zu)\n",
                        map->num_regions, num_fds);
                return -1;
            }

            /* Clean up previous table. */
            for (i = 0; i < be->num_regions; i++) {
                munmap(be->regions[i].mmap_addr,
                       be->regions[i].mmap_offset + be->regions[i].size);
            }
            memset(be->regions, 0, sizeof(be->regions));
            be->num_regions = 0;

            /* Setup the new table. */
            for (i = 0; i < map->num_regions; i++) {
                void *mmap_addr;

                be->regions[i].gpa_start = map->regions[i].guest_physical_addr;
                be->regions[i].size = map->regions[i].size;
                be->regions[i].gpa_end = be->regions[i].gpa_start +
                                         be->regions[i].size;
                be->regions[i].hv_vaddr =
                        map->regions[i].hypervisor_virtual_addr;
                be->regions[i].mmap_offset = map->regions[i].mmap_offset;

                /* We don't feed mmap_offset into the offset argument of
                 * mmap(), because the mapped address has to be page aligned,
                 * and we use huge pages. Instead, we map the file descriptor
                 * from the beginning, with a map size that includes the
                 * region of interest. */
                mmap_addr = mmap(0, /*size=*/be->regions[i].mmap_offset +
                                 be->regions[i].size, PROT_READ | PROT_WRITE,
                                 MAP_SHARED, /*fd=*/fds[i], /*offset=*/0);
                if (mmap_addr == MAP_FAILED) {
                    fprintf(stderr, "mmap(#%zu) failed: %s\n", i,
                            strerror(errno));
                    return -1;
                }
                be->regions[i].mmap_addr = mmap_addr;
                be->regions[i].va_start = mmap_addr +
                                          be->regions[i].mmap_offset;
            }
            be->num_regions = map->num_regions;

            if (verbose) {
                printf("Guest memory map:\n");
                for (i = 0; i < be->num_regions; i++) {
                    printf("    gpa %16"PRIx64", size %16"PRIu64", "
                           "hv_vaddr %16"PRIx64", mmap_ofs %16"PRIx64", "
                           "va_start %p\n",
                           be->regions[i].gpa_start, be->regions[i].size,
                           be->regions[i].hv_vaddr, be->regions[i].mmap_offset,
                           be->regions[i].va_start);
                }
            }
            break;
        }

        case BPFHV_PROXY_REQ_GET_PROGRAMS: {
            resp.hdr.size = 0;
            outfds[0] = open(be->ops.progfile, O_RDONLY, 0);
            if (outfds[0] < 0) {
                resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
                fprintf(stderr, "open(%s) failed: %s\n", be->ops.progfile,
                        strerror(errno));
                break;
            }
            num_outfds = 1;
            break;
        }

        case BPFHV_PROXY_REQ_SET_QUEUE_CTX: {
            uint64_t gpa = msg.payload.queue_ctx.guest_physical_addr;
            uint32_t queue_idx = msg.payload.queue_ctx.queue_idx;
            int is_rx = queue_idx < be->num_queue_pairs;
            size_t ctx_size;
            void *ctx;

            if (queue_idx >= be->num_queues) {
                resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
                fprintf(stderr, "Invalid queue idx %u\n", queue_idx);
                break;
            }

            if (be->num_rx_bufs == 0 || be->num_tx_bufs == 0) {
                resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
                fprintf(stderr, "Buffer numbers not negotiated\n");
                break;
            }

            if (is_rx) {
                ctx_size = be->ops.rx_ctx_size(be->num_rx_bufs);
            } else if (queue_idx < be->num_queues) {
                ctx_size = be->ops.tx_ctx_size(be->num_tx_bufs);
            }

            if (gpa != 0) {
                /* A GPA was provided, so let's try to translate it. */
                ctx = translate_addr(be, gpa, ctx_size);
                if (ctx == NULL) {
                    resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
                    fprintf(stderr, "Failed to translate gpa %"PRIx64"\n",
                                     gpa);
                    break;
                }
            } else {
                /* No GPA provided, which means that there is no context
                 * for this queue (yet). */
                ctx = NULL;
            }

            if (is_rx) {
                be->q[queue_idx].ctx.rx = (struct bpfhv_rx_context *)ctx;
                if (ctx) {
                    be->ops.rx_ctx_init(be->q[queue_idx].ctx.rx,
                                      be->num_rx_bufs);
                }
            } else {
                be->q[queue_idx].ctx.tx = (struct bpfhv_tx_context *)ctx;
                if (ctx) {
                    be->ops.tx_ctx_init(be->q[queue_idx].ctx.tx,
                                      be->num_tx_bufs);
                }
            }
            if (verbose) {
                printf("Set queue %s gpa to %"PRIx64", va %p\n",
                       be->q[queue_idx].name, gpa, ctx);
            }

            break;
        }

        case BPFHV_PROXY_REQ_SET_QUEUE_KICK:
        case BPFHV_PROXY_REQ_SET_QUEUE_IRQ: {
            int is_kick = msg.hdr.reqtype == BPFHV_PROXY_REQ_SET_QUEUE_KICK;
            uint32_t queue_idx = msg.payload.notify.queue_idx;
            int *fdp = NULL;

            if (queue_idx >= be->num_queues) {
                resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
                fprintf(stderr, "Invalid queue idx %u\n", queue_idx);
                break;
            }

            if (num_fds > 1) {
                resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
                fprintf(stderr, "Too many %sfds\n", is_kick ? "kick" : "irq");
                break;
            }

            fdp = is_kick ? &be->q[queue_idx].kickfd : &be->q[queue_idx].irqfd;

            /* Clean up previous file descriptor and install the new one. */
            if (*fdp >= 0) {
                close(*fdp);
            }
            *fdp = (num_fds == 1) ? fds[0] : -1;

            /* Steal it from the fds array to skip close(). */
            fds[0] = -1;

            if (verbose) {
                printf("Set queue %s %sfd to %d\n", be->q[queue_idx].name,
                       is_kick ? "kick" : "irq", *fdp);
            }

            break;
        }

        case BPFHV_PROXY_REQ_SET_UPGRADE: {
            if (num_fds != 1) {
                resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
                fprintf(stderr, "Missing upgrade fd\n");
                break;
            }

            /* Steal the file descriptor from the fds array to skip close(). */
            if (be->upgrade_fd >= 0) {
                close(be->upgrade_fd);
            }
            be->upgrade_fd = fds[0];
            fds[0] = -1;

            if (verbose) {
                printf("Set upgrade notifier to %d\n", be->upgrade_fd);
            }
            break;
        }

        case BPFHV_PROXY_REQ_RX_ENABLE:
        case BPFHV_PROXY_REQ_TX_ENABLE: {
            int is_rx = msg.hdr.reqtype == BPFHV_PROXY_REQ_RX_ENABLE;
            int ret;

            /* Check that backend is ready for packet processing. */
            if (!backend_ready(be)) {
                resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
                fprintf(stderr, "Cannot enable %s operation: backend is "
                        "not ready\n", is_rx ? "receive" : "transmit");
                break;
            }

            /* Update be->status. */
            if (is_rx) {
                be->status |= BPFHV_STATUS_RX_ENABLED;
            } else {
                be->status |= BPFHV_STATUS_TX_ENABLED;
            }

            if (be->running) {
                break;  /* Nothing to do */
            }

            /* Make sure that the processing thread sees stopflag == 0. */
            be->stopflag = 0;
            __atomic_thread_fence(__ATOMIC_RELEASE);

            ret = pthread_create(&be->th, NULL, process_packets, be);
            if (ret) {
                fprintf(stderr, "pthread_create() failed: %s\n",
                        strerror(ret));
                break;
            }
            be->running = 1;
            if (verbose) {
                printf("Backend starts processing\n");
            }
            break;
        }

        case BPFHV_PROXY_REQ_RX_DISABLE:
        case BPFHV_PROXY_REQ_TX_DISABLE: {
            int is_rx = msg.hdr.reqtype == BPFHV_PROXY_REQ_RX_DISABLE;
            int ret;

            /* Update be->status. */
            if (is_rx) {
                be->status &= ~BPFHV_STATUS_RX_ENABLED;
            } else {
                be->status &= ~BPFHV_STATUS_TX_ENABLED;
            }

            if (!be->running || ((be->status & (BPFHV_STATUS_RX_ENABLED |
                                BPFHV_STATUS_TX_ENABLED)) != 0)) {
                break;  /* Nothing to do. */
            }

            /* Notify the worker thread and join it. */
            ret = backend_stop(be);
            if (ret) {
                break;
            }

            /* Drain any remaining packets. */
            backend_drain(be);
            if (verbose) {
                printf("Backend stops processing\n");
            }
            break;
        }

        default:
            /* Not reached (see switch statement above). */
            assert(0);
            break;
        }

send_resp:
        /* Send back the response. */
        {
            char control[CMSG_SPACE(BPFHV_PROXY_MAX_REGIONS * sizeof(fds[0]))];
            size_t totsize = sizeof(resp.hdr) + resp.hdr.size;
            struct iovec iov = {
                .iov_base = &resp,
                .iov_len = totsize,
            };
            struct msghdr mh = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
            };

            if (num_outfds > 0) {
                /* Set ancillary data. */
                size_t data_size = num_outfds * sizeof(fds[0]);
                struct cmsghdr *cmsg;

                assert(num_outfds <= BPFHV_PROXY_MAX_REGIONS);

                mh.msg_control = control;
                mh.msg_controllen = CMSG_SPACE(data_size);

                cmsg = CMSG_FIRSTHDR(&mh);
                cmsg->cmsg_len = CMSG_LEN(data_size);
                cmsg->cmsg_level = SOL_SOCKET;
                cmsg->cmsg_type = SCM_RIGHTS;
                memcpy(CMSG_DATA(cmsg), outfds, data_size);
            }

            do {
                n = sendmsg(be->cfd, &mh, 0);
            } while (n < 0 && (errno == EINTR || errno == EAGAIN));
            if (n < 0) {
                fprintf(stderr, "sendmsg(cfd) failed: %s\n", strerror(errno));
                break;
            } else if (n != totsize) {
                fprintf(stderr, "Truncated send (%zu/%zu)\n", n, totsize);
                break;
            }
        }

        /* Close all the file descriptors passed as ancillary data. */
        {
            size_t i;

            for (i = 0; i < num_fds; i++) {
                if (fds[i] >= 0) {
                    close(fds[i]);
                }
            }
            for (i = 0; i < num_outfds; i++) {
                if (outfds[i] >= 0) {
                    close(outfds[i]);
                }
            }
        }
    }

    close(be->stopfd);

    return ret;
}

int
main(int argc, char **argv)
{
    struct sockaddr_un server_addr = { };
    const char *ifname = "tapx";
    const char *path = NULL;
    struct sigaction sa;
    int opt_offload = 0;
    int opt;
    int cfd;
    int ret;

    #ifdef PROXY_IDS
    proxy_ids_ini();
    #endif

    check_alignments();

    be.backend = "tap";
    be.device = "sring";
    be.pidfile = NULL;
    be.busy_wait = 0;
    be.befd = -1;
    be.collect_stats = 0;

    while ((opt = getopt(argc, argv, "hp:P:i:CGBvb:Su:d:O:")) != -1) {
        switch (opt) {
        case 'h':
            usage(argv[0]);
            return 0;

        case 'p':
            path = optarg;
            break;

        case 'P':
            be.pidfile = optarg;
            break;

        case 'i':
            ifname = optarg;
            break;

        case 'v':
            verbose++;
            break;

        case 'C':
            opt_offload |= OPT_TXCSUM | OPT_RXCSUM;
            break;

        case 'G':
            opt_offload |= OPT_TXCSUM | OPT_RXCSUM | OPT_TSO | OPT_LRO;
            break;

        case 'O': {
            char *s = optarg;
            char *token;

            for (;;) {
                token = strtok(s, ",");
                if (token == NULL) {
                    break;
                }
                s = NULL;
                if (!strcmp(token, "tso")) {
                    opt_offload |= OPT_TSO;
                } else if (!strcmp(token, "lro")) {
                    opt_offload |= OPT_LRO;
                } else if (!strcmp(token, "txcsum")) {
                    opt_offload |= OPT_TXCSUM;
                } else if (!strcmp(token, "rxcsum")) {
                    opt_offload |= OPT_RXCSUM;
                } else {
                    fprintf(stderr, "Unknown offload '%s'\n", token);
                    usage(argv[0]);
                    return -1;
                }
            }
            break;
        }

        case 'B':
            be.busy_wait = 1;
            break;

        case 'b':
            if (strcmp(optarg, "tap")
                && strcmp(optarg, "sink")
                && strcmp(optarg, "source")
#ifdef WITH_NETMAP
                && strcmp(optarg, "netmap")
#endif
            ) {
                fprintf(stderr, "Unknown backend type '%s'\n", optarg);
                usage(argv[0]);
                return -1;
            }
            be.backend = optarg;
            break;

        case 'd':
            if (strcmp(optarg, "sring")
                    && strcmp(optarg, "sring_gso")
                    && strcmp(optarg, "vring_packed")) {
                fprintf(stderr, "Unknown device type '%s'\n", optarg);
                usage(argv[0]);
                return -1;
            }
            be.device = optarg;
            break;

        case 'S':
            be.collect_stats = 1;
            break;

        case 'u':
            be.sleep_usecs = atoi(optarg);
            if (be.sleep_usecs < 0 || be.sleep_usecs > 1000) {
                fprintf(stderr, "-u option value must be in [0, 1000]\n");
                return -1;
            }
            break;

        default:
            usage(argv[0]);
            return -1;
            break;
        }
    }

    if (path == NULL) {
        fprintf(stderr, "Missing UNIX socket path\n");
        usage(argv[0]);
        return -1;
    }

    assert(sizeof(struct virtio_net_hdr_v1) == 12);

    if (be.pidfile != NULL) {
        FILE *f = fopen(be.pidfile, "w");

        if (f == NULL) {
            fprintf(stderr, "Failed to open pidfile: %s\n", strerror(errno));
            return -1;
        }

        fprintf(f, "%d", (int)getpid());
        fflush(f);
        fclose(f);
    }

    /* Set some signal handler for graceful termination. */
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    ret         = sigaction(SIGINT, &sa, NULL);
    if (ret) {
        perror("sigaction(SIGINT)");
        return ret;
    }
    ret = sigaction(SIGTERM, &sa, NULL);
    if (ret) {
        perror("sigaction(SIGTERM)");
        return ret;
    }

    /* Fix device type and offloads. */
    if (!strcmp(be.device, "sring") && (opt_offload)) {
        be.device = "sring_gso";
    }
    if (!strcmp(be.device, "vring_packed") && (opt_offload)) {
        opt_offload = 0;
    }

    /* Select device type ops. */
    if (!strcmp(be.device, "sring")) {
        be.ops = sring_ops;
    } else if (!strcmp(be.device, "sring_gso")) {
        be.ops = sring_gso_ops;
    } else if (!strcmp(be.device, "vring_packed")) {
        be.ops = vring_packed_ops;
    }
    be.features_avail = be.ops.features_avail;
    if (!(opt_offload & OPT_TXCSUM)) {
        be.features_avail &= ~(BPFHV_F_TX_CSUM);
    }
    if (!(opt_offload & OPT_RXCSUM)) {
        be.features_avail &= ~(BPFHV_F_RX_CSUM);
    }
    if (!(opt_offload & (OPT_TXCSUM | OPT_RXCSUM))) {
        be.features_avail &= ~(BPFHV_F_SG);
    }
    if (!(opt_offload & OPT_TSO)) {
        be.features_avail &= ~(BPFHV_F_TSOv4
                             | BPFHV_F_TSOv6
                             | BPFHV_F_UFO);
    }
    if (!(opt_offload & OPT_LRO)) {
        be.features_avail &= ~(BPFHV_F_TCPv4_LRO
                             | BPFHV_F_TCPv6_LRO
                             | BPFHV_F_UDP_LRO);
    }

    /* Select backend type. */
    be.vnet_hdr_len = (opt_offload) ?
        sizeof(struct virtio_net_hdr_v1) : 0;
    be.sync = NULL;
    if (!strcmp(be.backend, "tap")) {
        /* Open a TAP device to use as network backend. */
        be.befd = tap_alloc(ifname, be.vnet_hdr_len, opt_offload);
        if (be.befd < 0) {
            fprintf(stderr, "Failed to allocate TAP device\n");
            return -1;
        }
        be.recv = tap_recv;
        be.send = tap_send;
    } else if (!strcmp(be.backend, "sink")) {
        be.recv = null_recv;
        be.send = sink_send;
        be.befd = eventfd(0, 0);
        if (be.befd < 0) {
            fprintf(stderr, "Failed to allocate eventfd\n");
            return -1;
        }
    } else if (!strcmp(be.backend, "source")) {
        be.recv = source_recv;
        be.send = sink_send;
        be.befd = eventfd(1, 0);
        if (be.befd < 0) {
            fprintf(stderr, "Failed to allocate eventfd\n");
            return -1;
        }
    }
#ifdef WITH_NETMAP
    else if (!strcmp(be.backend, "netmap")) {
        /* Open a netmap port to use as network backend. */
        be.nm.port = nmport_open(ifname);
        if (be.nm.port == NULL) {
            fprintf(stderr, "nmport_open(%s) failed: %s\n", ifname,
                    strerror(errno));
            return -1;
        }
        assert(be.nm.port->register_done);
        assert(be.nm.port->mmap_done);
        assert(be.nm.port->fd >= 0);
        assert(be.nm.port->nifp != NULL);
        be.nm.txr = NETMAP_TXRING(be.nm.port->nifp, 0);
        be.nm.rxr = NETMAP_RXRING(be.nm.port->nifp, 0);
        be.befd = be.nm.port->fd;
        be.recv = netmap_recv;
        be.send = netmap_send;
        if (be.busy_wait) {
            be.sync = netmap_sync;
        }

        if (be.vnet_hdr_len > 0) {
            struct nmreq_port_hdr req;
            struct nmreq_header hdr;
            int ret;

            memcpy(&hdr, &be.nm.port->hdr, sizeof(hdr));
            hdr.nr_reqtype = NETMAP_REQ_PORT_HDR_SET;
            hdr.nr_body    = (uintptr_t)&req;
            memset(&req, 0, sizeof(req));
            req.nr_hdr_len = be.vnet_hdr_len;
            ret = ioctl(be.befd, NIOCCTRL, &hdr);
            if (ret != 0) {
                fprintf(stderr, "ioctl(/dev/netmap, NIOCCTRL, PORT_HDR_SET)");
                return ret;
            }
        }
    }
#endif

    cfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (cfd < 0) {
        fprintf(stderr, "socket(AF_UNIX) failed: %s\n", strerror(errno));
        return -1;
    }

    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, path, sizeof(server_addr.sun_path) - 1);

    if (connect(cfd, (const struct sockaddr *)&server_addr,
                sizeof(server_addr)) < 0) {
        fprintf(stderr, "connect(%s) failed: %s\n", path, strerror(errno));
        return -1;
    }

    be.cfd = cfd;

    if (verbose) {
        printf("device  : %s\n", be.device);
        printf("features: %"PRIx64"\n", be.features_avail);
        printf("backend : %s\n", be.backend);
        printf("vnethdr : %d\n", be.vnet_hdr_len);
    }

    ret = main_loop(&be);

    close(cfd);
    close(be.befd);
#ifdef WITH_NETMAP
    if (be.nm.port != NULL) {
        nmport_close(be.nm.port);
    }
#endif
    if (be.pidfile != NULL) {
        unlink(be.pidfile);
    }

    #ifdef PROXY_IDS
    proxy_ids_fini();
    #endif

    return ret;
}
#endif

#ifdef MULTI_BACKEND
static void
sigint_handler(int signum)
{
    uint32_t i;

    for(i = 0; i < bes_size; ++i) {
        if(bes[i].running) {
            if(verbose) {
                printf("Running backend %d interrupted\n", i);
            }
            backend_stop(&bes[i]);
            backend_drain(&bes[i]);
        }
        if(bes[i].pidfile != NULL) {
            unlink(bes[i].pidfile);
        }
    }
    exit(EXIT_SUCCESS);
}

static inline BpfhvBackend*
get_ready_backend(const int poll_timeout)
{
    struct pollfd pfds[MAX_BES_SIZE];
    uint32_t i;
    int poll_result;

    for(i = 0; i < bes_size; ++i) {
        pfds[i].fd = bes[i].cfd;
        pfds[i].events = POLLIN;
    }

    poll_result = poll(&pfds[0], bes_size, poll_timeout);

    if(unlikely(!poll_result)) {
        return NULL;
    } else if(unlikely(poll_result < 0)) {
        return GET_READY_BACKEND_FAIL;
    } else {
        for(i = 0; i < bes_size; ++i) {
            if(pfds[i].revents & POLLIN) {
                return &bes[i];
            }
        }
    }

    return NULL;
}

static int
main_loop()
{
    BpfhvBackend* be;
    int poll_timeout = -1;
    int ret = -1;
    int i;
    uint32_t be_index;

    for(be_index = 0; be_index < bes_size; ++be_index) {
        be = &bes[be_index];

        be->features_sel = 0;
        be->num_queue_pairs = be->num_queues = 0;
        be->num_rx_bufs = 0;
        be->num_tx_bufs = 0;
        be->running = 0;
        be->status = 0;
        be->upgrade_fd = -1;

        for (i = 0; i < BPFHV_MAX_QUEUES; i++) {
            be->q[i].ctx.rx = NULL;
            be->q[i].kickfd = be->q[i].irqfd = -1;
        }

        be->stopfd = eventfd(0, 0);
        if (be->stopfd < 0) {
            fprintf(stderr, "eventfd() failed: %s\nbe_index: %d\n", strerror(errno), be_index);
            return -1;
        }
        be->stopflag = 0;

        ret = fcntl(be->stopfd, F_SETFL, O_NONBLOCK);
        if (ret) {
            fprintf(
                stderr, "fcntl(stopfd, F_SETFL) failed: %s\nbe_index: %d\n",
                strerror(errno), be_index
            );
            return -1;
        }

        ret = fcntl(be->befd, F_SETFL, O_NONBLOCK);
        if (ret) {
            fprintf(
                stderr, "fcntl(befd, F_SETFL) failed: %s\nbe_index: %d\n",
                strerror(errno), be_index
            );
            return -1;
        }

        gettimeofday(&be->stats_ts, NULL);

        if(be->collect_stats) {
            poll_timeout = 2000;/*ms*/
        }
    }

    for (;;) {
        ssize_t payload_size = 0;
        BpfhvProxyMessage resp = { };

        /* Variables to store recvmsg() ancillary data. */
        int fds[BPFHV_PROXY_MAX_REGIONS] = { };
        size_t num_fds = 0;

        /* Variables to store sendmsg() ancillary data. */
        int outfds[BPFHV_PROXY_MAX_REGIONS] = { };
        size_t num_outfds = 0;

        /* Support variables for reading a bpfhv-proxy message header. */
        char control[CMSG_SPACE(BPFHV_PROXY_MAX_REGIONS * sizeof(fds[0]))] = {};
        BpfhvProxyMessage msg = { };
        struct iovec iov = {
            .iov_base = &msg.hdr,
            .iov_len = sizeof(msg.hdr),
        };
        struct msghdr mh = {
            .msg_iov = &iov,
            .msg_iovlen = 1,
            .msg_control = control,
            .msg_controllen = sizeof(control),
        };
        struct cmsghdr *cmsg;
        ssize_t n;

        /* Wait for the next message to arrive. */
        be = get_ready_backend(poll_timeout);
        if (unlikely(!be)) {
            /* Timeout. We need to compute and show statistics. */
            for(i = 0; i < bes_size; ++i) {
                if(bes[i].running) {
                    stats_show(&bes[i]);
                }
            }
            continue;
        } else if (unlikely(be == GET_READY_BACKEND_FAIL)) {
            break;
        }

        /* Read a bpfhv-proxy message header plus ancillary data. */
        do {
            n = recvmsg(be->cfd, &mh, 0);
        } while (n < 0 && (errno == EINTR || errno == EAGAIN));
        if (n < 0) {
            fprintf(stderr, "recvmsg(cfd) failed: %s\n", strerror(errno));
            break;
        }

        if (n == 0) {
            /* EOF */
            if (verbose) {
                printf("Connection closed by the hypervisor\n");
            }
            break;
        }

        /* Scan ancillary data looking for file descriptors. */
        for (cmsg = CMSG_FIRSTHDR(&mh); cmsg != NULL;
                cmsg = CMSG_NXTHDR(&mh, cmsg)) {
            if (cmsg->cmsg_level == SOL_SOCKET &&
                    cmsg->cmsg_type == SCM_RIGHTS) {
                size_t arr_size = cmsg->cmsg_len - CMSG_LEN(0);

                num_fds = arr_size / sizeof(fds[0]);
                if (num_fds > BPFHV_PROXY_MAX_REGIONS) {
                    fprintf(stderr, "Message contains too much ancillary data "
                            "(%zu file descriptors)\n", num_fds);
                    return -1;
                }
                memcpy(fds, CMSG_DATA(cmsg), arr_size);

                break; /* Discard any other ancillary data. */
            }
        }

        if (n < (ssize_t)sizeof(msg.hdr)) {
            fprintf(stderr, "Message too short (%zd bytes)\n", n);
            break;
        }

        if ((msg.hdr.flags & BPFHV_PROXY_F_VERSION_MASK)
                != BPFHV_PROXY_VERSION) {
            fprintf(stderr, "Protocol version mismatch: expected %u, got %u",
                    BPFHV_PROXY_VERSION,
                    msg.hdr.flags & BPFHV_PROXY_F_VERSION_MASK);
            break;
        }

        /* Check that payload size is correct. */
        switch (msg.hdr.reqtype) {
        case BPFHV_PROXY_REQ_GET_FEATURES:
        case BPFHV_PROXY_REQ_GET_PROGRAMS:
        case BPFHV_PROXY_REQ_RX_ENABLE:
        case BPFHV_PROXY_REQ_TX_ENABLE:
        case BPFHV_PROXY_REQ_RX_DISABLE:
        case BPFHV_PROXY_REQ_TX_DISABLE:
            payload_size = 0;
            break;

        case BPFHV_PROXY_REQ_SET_FEATURES:
            payload_size = sizeof(msg.payload.u64);
            break;

        case BPFHV_PROXY_REQ_SET_PARAMETERS:
            payload_size = sizeof(msg.payload.params);
            break;

        case BPFHV_PROXY_REQ_SET_MEM_TABLE:
            payload_size = sizeof(msg.payload.memory_map);
            break;

        case BPFHV_PROXY_REQ_SET_QUEUE_CTX:
            payload_size = sizeof(msg.payload.queue_ctx);
            break;

        case BPFHV_PROXY_REQ_SET_QUEUE_KICK:
        case BPFHV_PROXY_REQ_SET_QUEUE_IRQ:
        case BPFHV_PROXY_REQ_SET_UPGRADE:
            payload_size = sizeof(msg.payload.notify);
            break;

        default:
            fprintf(stderr, "Invalid request type (%d)\n", msg.hdr.reqtype);
            return -1;
        }

        if (payload_size != msg.hdr.size) {
            fprintf(stderr, "Payload size mismatch: expected %zd, got %u\n",
                    payload_size, msg.hdr.size);
            break;
        }

        /* Read payload. */
        do {
            n = read(be->cfd, &msg.payload, payload_size);
        } while (n < 0 && (errno == EINTR || errno == EAGAIN));
        if (n < 0) {
            fprintf(stderr, "read(cfd, payload) failed: %s\n",
                    strerror(errno));
            break;
        }

        if (n != payload_size) {
            fprintf(stderr, "Truncated payload: expected %zd bytes, "
                    "but only %zd were read\n", payload_size, n);
            break;
        }

        resp.hdr.reqtype = msg.hdr.reqtype;
        resp.hdr.flags = BPFHV_PROXY_VERSION;

        /* Check if this request is acceptable while the backend
         * is running. */
        switch (msg.hdr.reqtype) {
        case BPFHV_PROXY_REQ_SET_FEATURES:
        case BPFHV_PROXY_REQ_SET_PARAMETERS:
        case BPFHV_PROXY_REQ_SET_QUEUE_CTX:
        case BPFHV_PROXY_REQ_SET_QUEUE_KICK:
            if (be->running) {
                fprintf(stderr, "Cannot accept request because backend "
                                "is running\n");
                resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
                goto send_resp;
            }
            break;
        default:
            break;
        }

        /* Process the request. */
        switch (msg.hdr.reqtype) {
        case BPFHV_PROXY_REQ_SET_FEATURES:
            be->features_sel = be->features_avail & msg.payload.u64;
            if (verbose) {
                printf("Negotiated features %"PRIx64"\n", be->features_sel);
            }
            if (be->features_sel &
                    (BPFHV_F_TCPv4_LRO | BPFHV_F_TCPv6_LRO | BPFHV_F_UDP_LRO)) {
                be->max_rx_pkt_size = 65536;
            } else {
                be->max_rx_pkt_size = 1518;
            }
            /* TODO We should also set be->vnet_hdr_len here ... */

            break;

        case BPFHV_PROXY_REQ_GET_FEATURES:
            resp.hdr.size = sizeof(resp.payload.u64);
            resp.payload.u64 = be->features_avail;
            break;

        case BPFHV_PROXY_REQ_SET_PARAMETERS: {
            BpfhvProxyParameters *params = &msg.payload.params;

            if (params->num_rx_queues != 1 || params->num_tx_queues != 1) {
                resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
            } else if (!num_bufs_valid(params->num_rx_bufs) ||
                       !num_bufs_valid(params->num_tx_bufs)) {
                resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
            } else {
                unsigned int i;

                be->num_queue_pairs = (unsigned int)params->num_rx_queues;
                be->num_rx_bufs = (unsigned int)params->num_rx_bufs;
                be->num_tx_bufs = (unsigned int)params->num_tx_bufs;
                if (verbose) {
                    printf("Set queue parameters: %u queue pairs, %u rx bufs, "
                          "%u tx bufs\n", be->num_queue_pairs,
                           be->num_rx_bufs, be->num_tx_bufs);
                }

                be->num_queues = 2 * be->num_queue_pairs;

                resp.hdr.size = sizeof(resp.payload.ctx_sizes);
                resp.payload.ctx_sizes.rx_ctx_size =
                    be->ops.rx_ctx_size(be->num_rx_bufs);
                resp.payload.ctx_sizes.tx_ctx_size =
                    be->ops.tx_ctx_size(be->num_tx_bufs);

                for (i = RXI_BEGIN(be); i < RXI_END(be); i++) {
                    snprintf(be->q[i].name, sizeof(be->q[i].name),
                             "RX%u", i);
                }
                for (i = TXI_BEGIN(be); i < TXI_END(be); i++) {
                    snprintf(be->q[i].name, sizeof(be->q[i].name),
                             "TX%u", i-be->num_queue_pairs);
                }
            }
            break;
        }

        case BPFHV_PROXY_REQ_SET_MEM_TABLE: {
            BpfhvProxyMemoryMap *map = &msg.payload.memory_map;
            size_t i;

            /* Perform sanity checks. */
            if (map->num_regions > BPFHV_PROXY_MAX_REGIONS) {
                resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
                fprintf(stderr, "Too many memory regions: %u\n",
                        map->num_regions);
                return -1;
            }
            if (num_fds != map->num_regions) {
                resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
                fprintf(stderr, "Mismatch between number of regions (%u) and "
                        "number of file descriptors (%zu)\n",
                        map->num_regions, num_fds);
                return -1;
            }

            /* Clean up previous table. */
            for (i = 0; i < be->num_regions; i++) {
                munmap(be->regions[i].mmap_addr,
                       be->regions[i].mmap_offset + be->regions[i].size);
            }
            memset(be->regions, 0, sizeof(be->regions));
            be->num_regions = 0;

            /* Setup the new table. */
            for (i = 0; i < map->num_regions; i++) {
                void *mmap_addr;

                be->regions[i].gpa_start = map->regions[i].guest_physical_addr;
                be->regions[i].size = map->regions[i].size;
                be->regions[i].gpa_end = be->regions[i].gpa_start +
                                         be->regions[i].size;
                be->regions[i].hv_vaddr =
                        map->regions[i].hypervisor_virtual_addr;
                be->regions[i].mmap_offset = map->regions[i].mmap_offset;

                /* We don't feed mmap_offset into the offset argument of
                 * mmap(), because the mapped address has to be page aligned,
                 * and we use huge pages. Instead, we map the file descriptor
                 * from the beginning, with a map size that includes the
                 * region of interest. */
                mmap_addr = mmap(0, /*size=*/be->regions[i].mmap_offset +
                                 be->regions[i].size, PROT_READ | PROT_WRITE,
                                 MAP_SHARED, /*fd=*/fds[i], /*offset=*/0);
                if (mmap_addr == MAP_FAILED) {
                    fprintf(stderr, "mmap(#%zu) failed: %s\n", i,
                            strerror(errno));
                    return -1;
                }
                be->regions[i].mmap_addr = mmap_addr;
                be->regions[i].va_start = mmap_addr +
                                          be->regions[i].mmap_offset;
            }
            be->num_regions = map->num_regions;

            if (verbose) {
                printf("Guest memory map:\n");
                for (i = 0; i < be->num_regions; i++) {
                    printf("    gpa %16"PRIx64", size %16"PRIu64", "
                           "hv_vaddr %16"PRIx64", mmap_ofs %16"PRIx64", "
                           "va_start %p\n",
                           be->regions[i].gpa_start, be->regions[i].size,
                           be->regions[i].hv_vaddr, be->regions[i].mmap_offset,
                           be->regions[i].va_start);
                }
            }
            break;
        }

        case BPFHV_PROXY_REQ_GET_PROGRAMS: {
            resp.hdr.size = 0;
            outfds[0] = open(be->ops.progfile, O_RDONLY, 0);
            if (outfds[0] < 0) {
                resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
                fprintf(stderr, "open(%s) failed: %s\n", be->ops.progfile,
                        strerror(errno));
                break;
            }
            num_outfds = 1;
            break;
        }

        case BPFHV_PROXY_REQ_SET_QUEUE_CTX: {
            uint64_t gpa = msg.payload.queue_ctx.guest_physical_addr;
            uint32_t queue_idx = msg.payload.queue_ctx.queue_idx;
            int is_rx = queue_idx < be->num_queue_pairs;
            size_t ctx_size;
            void *ctx;

            if (queue_idx >= be->num_queues) {
                resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
                fprintf(stderr, "Invalid queue idx %u\n", queue_idx);
                break;
            }

            if (be->num_rx_bufs == 0 || be->num_tx_bufs == 0) {
                resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
                fprintf(stderr, "Buffer numbers not negotiated\n");
                break;
            }

            if (is_rx) {
                ctx_size = be->ops.rx_ctx_size(be->num_rx_bufs);
            } else if (queue_idx < be->num_queues) {
                ctx_size = be->ops.tx_ctx_size(be->num_tx_bufs);
            }

            if (gpa != 0) {
                /* A GPA was provided, so let's try to translate it. */
                ctx = translate_addr(be, gpa, ctx_size);
                if (ctx == NULL) {
                    resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
                    fprintf(stderr, "Failed to translate gpa %"PRIx64"\n",
                                     gpa);
                    break;
                }
            } else {
                /* No GPA provided, which means that there is no context
                 * for this queue (yet). */
                ctx = NULL;
            }

            if (is_rx) {
                be->q[queue_idx].ctx.rx = (struct bpfhv_rx_context *)ctx;
                if (ctx) {
                    be->ops.rx_ctx_init(be->q[queue_idx].ctx.rx,
                                      be->num_rx_bufs);
                }
            } else {
                be->q[queue_idx].ctx.tx = (struct bpfhv_tx_context *)ctx;
                if (ctx) {
                    be->ops.tx_ctx_init(be->q[queue_idx].ctx.tx,
                                      be->num_tx_bufs);
                }
            }
            if (verbose) {
                printf("Set queue %s gpa to %"PRIx64", va %p\n",
                       be->q[queue_idx].name, gpa, ctx);
            }

            break;
        }

        case BPFHV_PROXY_REQ_SET_QUEUE_KICK:
        case BPFHV_PROXY_REQ_SET_QUEUE_IRQ: {
            int is_kick = msg.hdr.reqtype == BPFHV_PROXY_REQ_SET_QUEUE_KICK;
            uint32_t queue_idx = msg.payload.notify.queue_idx;
            int *fdp = NULL;

            if (queue_idx >= be->num_queues) {
                resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
                fprintf(stderr, "Invalid queue idx %u\n", queue_idx);
                break;
            }

            if (num_fds > 1) {
                resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
                fprintf(stderr, "Too many %sfds\n", is_kick ? "kick" : "irq");
                break;
            }

            fdp = is_kick ? &be->q[queue_idx].kickfd : &be->q[queue_idx].irqfd;

            /* Clean up previous file descriptor and install the new one. */
            if (*fdp >= 0) {
                close(*fdp);
            }
            *fdp = (num_fds == 1) ? fds[0] : -1;

            /* Steal it from the fds array to skip close(). */
            fds[0] = -1;

            if (verbose) {
                printf("Set queue %s %sfd to %d\n", be->q[queue_idx].name,
                       is_kick ? "kick" : "irq", *fdp);
            }

            break;
        }

        case BPFHV_PROXY_REQ_SET_UPGRADE: {
            if (num_fds != 1) {
                resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
                fprintf(stderr, "Missing upgrade fd\n");
                break;
            }

            /* Steal the file descriptor from the fds array to skip close(). */
            if (be->upgrade_fd >= 0) {
                close(be->upgrade_fd);
            }
            be->upgrade_fd = fds[0];
            fds[0] = -1;

            if (verbose) {
                printf("Set upgrade notifier to %d\n", be->upgrade_fd);
            }
            break;
        }

        case BPFHV_PROXY_REQ_RX_ENABLE:
        case BPFHV_PROXY_REQ_TX_ENABLE: {
            int is_rx = msg.hdr.reqtype == BPFHV_PROXY_REQ_RX_ENABLE;
            int ret;

            /* Check that backend is ready for packet processing. */
            if (!backend_ready(be)) {
                resp.hdr.flags |= BPFHV_PROXY_F_ERROR;
                fprintf(stderr, "Cannot enable %s operation: backend is "
                        "not ready\n", is_rx ? "receive" : "transmit");
                break;
            }

            /* Update be->status. */
            if (is_rx) {
                be->status |= BPFHV_STATUS_RX_ENABLED;
            } else {
                be->status |= BPFHV_STATUS_TX_ENABLED;
            }

            if (be->running) {
                break;  /* Nothing to do */
            }

            /* Make sure that the processing thread sees stopflag == 0. */
            be->stopflag = 0;
            __atomic_thread_fence(__ATOMIC_RELEASE);

            ret = pthread_create(&be->th, NULL, process_packets, be);
            if (ret) {
                fprintf(stderr, "pthread_create() failed: %s\n",
                        strerror(ret));
                break;
            }
            be->running = 1;
            if (verbose) {
                printf("Backend starts processing\n");
            }
            break;
        }

        case BPFHV_PROXY_REQ_RX_DISABLE:
        case BPFHV_PROXY_REQ_TX_DISABLE: {
            int is_rx = msg.hdr.reqtype == BPFHV_PROXY_REQ_RX_DISABLE;
            int ret;

            /* Update be->status. */
            if (is_rx) {
                be->status &= ~BPFHV_STATUS_RX_ENABLED;
            } else {
                be->status &= ~BPFHV_STATUS_TX_ENABLED;
            }

            if (!be->running || ((be->status & (BPFHV_STATUS_RX_ENABLED |
                                BPFHV_STATUS_TX_ENABLED)) != 0)) {
                break;  /* Nothing to do. */
            }

            /* Notify the worker thread and join it. */
            ret = backend_stop(be);
            if (ret) {
                break;
            }

            /* Drain any remaining packets. */
            backend_drain(be);
            if (verbose) {
                printf("Backend stops processing\n");
            }
            break;
        }

        default:
            /* Not reached (see switch statement above). */
            assert(0);
            break;
        }

send_resp:
        /* Send back the response. */
        {
            char control[CMSG_SPACE(BPFHV_PROXY_MAX_REGIONS * sizeof(fds[0]))];
            size_t totsize = sizeof(resp.hdr) + resp.hdr.size;
            struct iovec iov = {
                .iov_base = &resp,
                .iov_len = totsize,
            };
            struct msghdr mh = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
            };

            if (num_outfds > 0) {
                /* Set ancillary data. */
                size_t data_size = num_outfds * sizeof(fds[0]);
                struct cmsghdr *cmsg;

                assert(num_outfds <= BPFHV_PROXY_MAX_REGIONS);

                mh.msg_control = control;
                mh.msg_controllen = CMSG_SPACE(data_size);

                cmsg = CMSG_FIRSTHDR(&mh);
                cmsg->cmsg_len = CMSG_LEN(data_size);
                cmsg->cmsg_level = SOL_SOCKET;
                cmsg->cmsg_type = SCM_RIGHTS;
                memcpy(CMSG_DATA(cmsg), outfds, data_size);
            }

            do {
                n = sendmsg(be->cfd, &mh, 0);
            } while (n < 0 && (errno == EINTR || errno == EAGAIN));
            if (n < 0) {
                fprintf(stderr, "sendmsg(cfd) failed: %s\n", strerror(errno));
                break;
            } else if (n != totsize) {
                fprintf(stderr, "Truncated send (%zu/%zu)\n", n, totsize);
                break;
            }
        }

        /* Close all the file descriptors passed as ancillary data. */
        {
            size_t i;

            for (i = 0; i < num_fds; i++) {
                if (fds[i] >= 0) {
                    close(fds[i]);
                }
            }
            for (i = 0; i < num_outfds; i++) {
                if (outfds[i] >= 0) {
                    close(outfds[i]);
                }
            }
        }
    }

    close(be->stopfd);

    return ret;
}

int
main(int argc, char** argv)
{
    struct sockaddr_un server_addrs[MAX_BES_SIZE];
    const char* ifnames[MAX_BES_SIZE];
    const char* paths[MAX_BES_SIZE];
    struct sigaction sa;
    uint32_t i;
    int opt_offload = 0;
    int opt;
    int ret;

    #ifdef PROXY_IDS
    proxy_ids_ini();
    #endif

    check_alignments();

    // Default initialization
    memset(&server_addrs[0], 0x00, sizeof(struct sockaddr_un) * MAX_BES_SIZE);
    ifnames[0] = 0;
    paths[0] = 0;
    bes_size = MAX_BES_SIZE;
    bes = malloc(sizeof(*bes) * bes_size);
    for(i = 0; i < bes_size; ++i) {
        bes[i].backend = "tap";
        bes[i].device = "sring";
        bes[i].pidfile = NULL;
        bes[i].busy_wait = 0;
        bes[i].befd = -1;
        bes[i].collect_stats = 0;
    }

    while ((opt = getopt(argc, argv, "hp:P:i:CGBvb:Su:d:O:")) != -1) {
        switch (opt) {
        case 'h':
            usage(argv[0]);
            return 0;

        case 'p': {
            char* token;

            if(!optarg) {
                usage(argv[0]);
                return -1;
            }

            token = strtok(optarg, ",");
            bes_size = 0;
            while(token && bes_size < 128) {
                paths[bes_size] = token;
                fprintf(stderr, "paths[%d]: %s\n", bes_size, paths[bes_size]);
                ++bes_size;
                token = strtok(NULL, ",");
            }
            paths[bes_size] = 0;
            break;
        }

        case 'P':
            //be.pidfile = optarg;
            fprintf(stderr, "Option -P is unsopported\n");
            break;

        case 'i': {
            char* token;

            if(!optarg) {
                usage(argv[0]);
                return -1;
            }

            token = strtok(optarg, ",");
            bes_size = 0;
            while(token && bes_size < 128) {
                ifnames[bes_size] = token;
                fprintf(stderr, "ifnames[%d]: %s\n", bes_size, ifnames[bes_size]);
                ++bes_size;
                token = strtok(NULL, ",");
            }
            ifnames[bes_size] = 0;
            break;
        }

        case 'v':
            verbose++;
            break;

        case 'C':
            opt_offload |= OPT_TXCSUM | OPT_RXCSUM;
            break;

        case 'G':
            opt_offload |= OPT_TXCSUM | OPT_RXCSUM | OPT_TSO | OPT_LRO;
            break;

        case 'O': {
            char *s = optarg;
            char *token;

            for (;;) {
                token = strtok(s, ",");
                if (token == NULL) {
                    break;
                }
                s = NULL;
                if (!strcmp(token, "tso")) {
                    opt_offload |= OPT_TSO;
                } else if (!strcmp(token, "lro")) {
                    opt_offload |= OPT_LRO;
                } else if (!strcmp(token, "txcsum")) {
                    opt_offload |= OPT_TXCSUM;
                } else if (!strcmp(token, "rxcsum")) {
                    opt_offload |= OPT_RXCSUM;
                } else {
                    fprintf(stderr, "Unknown offload '%s'\n", token);
                    usage(argv[0]);
                    return -1;
                }
            }
            break;
        }

        case 'B':
            SET_ALL_BES(busy_wait, 1);
            break;

        case 'b':
            if (strcmp(optarg, "tap")
                && strcmp(optarg, "sink")
                && strcmp(optarg, "source")
#ifdef WITH_NETMAP
                && strcmp(optarg, "netmap")
#endif
            ) {
                fprintf(stderr, "Unknown backend type '%s'\n", optarg);
                usage(argv[0]);
                return -1;
            }
            SET_ALL_BES(backend, optarg);
            break;

        case 'd':
            if (strcmp(optarg, "sring")
                    && strcmp(optarg, "sring_gso")
                    && strcmp(optarg, "vring_packed")) {
                fprintf(stderr, "Unknown device type '%s'\n", optarg);
                usage(argv[0]);
                return -1;
            }
            SET_ALL_BES(device, optarg);
            break;

        case 'S':
            SET_ALL_BES(collect_stats, 1);
            break;

        case 'u': {
            int time = atoi(optarg);
            if (time < 0 || time > 1000) {
                fprintf(stderr, "-u option value must be in [0, 1000]\n");
                return -1;
            }
            SET_ALL_BES(sleep_usecs, time);
            break;
        }

        default:
            usage(argv[0]);
            return -1;
            break;
        }
    }

    if(paths[0] == NULL) {
        fprintf(stderr, "Missing UNIX socket path(s)\n");
        usage(argv[0]);
        return -1;
    }

    if(ifnames[0] == NULL) {
        fprintf(stderr, "Missing interface name(s)\n");
        usage(argv[0]);
        return -1;
    }

    assert(sizeof(struct virtio_net_hdr_v1) == 12);

    /*if (be.pidfile != NULL) {
        FILE *f = fopen(be.pidfile, "w");

        if (f == NULL) {
            fprintf(stderr, "Failed to open pidfile: %s\n", strerror(errno));
            return -1;
        }

        fprintf(f, "%d", (int)getpid());
        fflush(f);
        fclose(f);
    }*/

    /* Set some signal handler for graceful termination. */
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    ret         = sigaction(SIGINT, &sa, NULL);
    if (ret) {
        perror("sigaction(SIGINT)");
        return ret;
    }
    ret = sigaction(SIGTERM, &sa, NULL);
    if (ret) {
        perror("sigaction(SIGTERM)");
        return ret;
    }

    /* Fix device type and offloads. */
    if (!strcmp(bes[0].device, "sring") && (opt_offload)) {
        SET_ALL_BES(device, "sring_gso");
    }
    if (!strcmp(bes[0].device, "vring_packed") && (opt_offload)) {
        opt_offload = 0;
    }

    /* Select device type ops. */
    if (!strcmp(bes[0].device, "sring")) {
        ALL_BES.ops = sring_ops;
    } else if (!strcmp(bes[0].device, "sring_gso")) {
        ALL_BES.ops = sring_gso_ops;
    } else if (!strcmp(bes[0].device, "vring_packed")) {
        ALL_BES.ops = vring_packed_ops;
    }
    ALL_BES.features_avail = bes[0].ops.features_avail;
    if (!(opt_offload & OPT_TXCSUM)) {
        ALL_BES.features_avail &= ~(BPFHV_F_TX_CSUM);
    }
    if (!(opt_offload & OPT_RXCSUM)) {
        ALL_BES.features_avail &= ~(BPFHV_F_RX_CSUM);
    }
    if (!(opt_offload & (OPT_TXCSUM | OPT_RXCSUM))) {
        ALL_BES.features_avail &= ~(BPFHV_F_SG);
    }
    if (!(opt_offload & OPT_TSO)) {
        ALL_BES.features_avail &= ~(BPFHV_F_TSOv4 | BPFHV_F_TSOv6 | BPFHV_F_UFO);
    }
    if (!(opt_offload & OPT_LRO)) {
        ALL_BES.features_avail &= ~(BPFHV_F_TCPv4_LRO | BPFHV_F_TCPv6_LRO | BPFHV_F_UDP_LRO);
    }

    /* Select backend type. */
    ALL_BES.vnet_hdr_len = (opt_offload) ? sizeof(struct virtio_net_hdr_v1) : 0;
    ALL_BES.sync = NULL;
    if (!strcmp(bes[0].backend, "tap")) {
        /* Open TAP devices to use them as network backends. */
        for(i = 0; i < bes_size; ++i) {
            bes[i].befd = tap_alloc(ifnames[i], bes[i].vnet_hdr_len, opt_offload);
            if (bes[i].befd < 0) {
                fprintf(stderr, "Failed to allocate TAP device (interface name: %s)\n", ifnames[i]);
                return -1;
            }
            bes[i].recv = tap_recv;
            bes[i].send = tap_send;
        }
    } else if (!strcmp(bes[0].backend, "sink")) {
        for(i = 0; i < bes_size; ++i) {
            bes[i].recv = null_recv;
            bes[i].send = sink_send;
            bes[i].befd = eventfd(0, 0);
            if (bes[i].befd < 0) {
                fprintf(stderr, "Failed to allocate eventfd\n");
                return -1;
            }
        }
    } else if (!strcmp(bes[0].backend, "source")) {
        for(i = 0; i < bes_size; ++i) {
            bes[i].recv = source_recv;
            bes[i].send = sink_send;
            bes[i].befd = eventfd(1, 0);
            if (bes[i].befd < 0) {
                fprintf(stderr, "Failed to allocate eventfd\n");
                return -1;
            }
        }
    }
#ifdef WITH_NETMAP
    else if (!strcmp(bes[0].backend, "netmap")) {
        for(i = 0; i < bes_size; ++i) {
            // Open a netmap port to use as network backend.
            bes[i].nm.port = nmport_open(ifnames[i]);
            if (bes[i].nm.port == NULL) {
                fprintf(stderr, "nmport_open(%s) failed: %s\n", ifnames[i], strerror(errno));
                return -1;
            }
            assert(bes[i].nm.port->register_done);
            assert(bes[i].nm.port->mmap_done);
            assert(bes[i].nm.port->fd >= 0);
            assert(bes[i].nm.port->nifp != NULL);
            bes[i].nm.txr = NETMAP_TXRING(bes[i].nm.port->nifp, 0);
            bes[i].nm.rxr = NETMAP_RXRING(bes[i].nm.port->nifp, 0);
            bes[i].befd = bes[i].nm.port->fd;
            bes[i].recv = netmap_recv;
            bes[i].send = netmap_send;
            if (bes[i].busy_wait) {
                bes[i].sync = netmap_sync;
            }

            if (bes[i].vnet_hdr_len > 0) {
                struct nmreq_port_hdr req;
                struct nmreq_header hdr;
                int ret;

                memcpy(&hdr, &bes[i].nm.port->hdr, sizeof(hdr));
                hdr.nr_reqtype = NETMAP_REQ_PORT_HDR_SET;
                hdr.nr_body    = (uintptr_t)&req;
                memset(&req, 0, sizeof(req));
                req.nr_hdr_len = bes[i].vnet_hdr_len;
                ret = ioctl(bes[i].befd, NIOCCTRL, &hdr);
                if (ret != 0) {
                    fprintf(stderr, "ioctl(/dev/netmap, NIOCCTRL, PORT_HDR_SET)");
                    return ret;
                }
            }
        }
    }
#endif

    // Connect to all instance of QEMU
    printf("Waiting for the connection of %d guests\n", bes_size);
    for(i = 0; i < bes_size; ++i) {
        int cfd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (cfd < 0) {
            fprintf(stderr, "socket(AF_UNIX) failed: %s\ni: %d\n", strerror(errno), i);
            return -1;
        }

        server_addrs[i].sun_family = AF_UNIX;
        strncpy(server_addrs[i].sun_path, paths[i], sizeof(server_addrs[i].sun_path) - 1);

        if(connect(cfd, (const struct sockaddr *)&server_addrs[i], sizeof(server_addrs[i])) < 0) {
            fprintf(stderr, "connect(%s) failed: %s\ni: %d\n", paths[i], strerror(errno), i);
            return -1;
        }

        bes[i].cfd = cfd;

        printf("Guest %d just connected!\n", i);

        if(verbose) {
            printf("device   : %s\n", bes[i].device);
            printf("features : %"PRIx64"\n", bes[i].features_avail);
            printf("backend  : %s\n", bes[i].backend);
            printf("vnethdr  : %d\n", bes[i].vnet_hdr_len);
        }
    }

    ret = main_loop();

    for(i = 0; i < bes_size; ++i) {
        close(bes[i].cfd);
        close(bes[i].befd);
#ifdef WITH_NETMAP
        if (bes[i].nm.port != NULL) {
            nmport_close(bes[i].nm.port);
        }
#endif
        if(bes[i].pidfile != NULL) {
            unlink(bes[i].pidfile);
        }
    }

    #ifdef PROXY_IDS
    proxy_ids_fini();
    #endif

    return ret;
}
#endif
