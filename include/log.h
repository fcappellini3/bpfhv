#ifndef __LOG_H__
#define __LOG_H__


#define TIMER_DATA_STRUCT struct timeval t0, t1
#define STATIC_TIMER_DATA_STRUCT static TIMER_DATA_STRUCT
#define TIMER_VALUE() ((double)((t1.tv_sec - t0.tv_sec)) * 1000.0d + (double)((t1.tv_usec - t0.tv_usec)) / 1000.0d)
#define TIMER_VALUE_US() ((uint64_t)((t1.tv_sec - t0.tv_sec) * 1000 * 1000 + (t1.tv_usec - t0.tv_usec)))


#ifdef __KERNEL__

#if defined(DEBUG_LEVEL) && DEBUG_LEVEL > 0
#define print_debug(args...) printk(KERN_ERR args)
#else
#define print_debug(args...) do{} while(0)
#endif

#define print_error(args...)  printk(KERN_ERR args)
#define print_always(args...) printk(KERN_ERR args)

#define TIMER_START() do_gettimeofday(&t0)
#define TIMER_STOP()  do_gettimeofday(&t1)

#else

#if defined(DEBUG_LEVEL) && DEBUG_LEVEL > 0
#define print_debug(args...) fprintf(stderr, args)
#else
#define print_debug(args...) do{} while(0)
#endif

#define print_error(args...)  fprintf(stderr, args)
#define print_always(args...) fprintf(stderr, args)

#define TIMER_START gettimeofday(&t0)
#define TIMER_STOP  gettimeofday(&t1)

#endif


#endif
