#ifndef __LOG_H__
#define __LOG_H__


#ifdef __KERNEL__

#if defined(DEBUG_LEVEL) && DEBUG_LEVEL > 0
#define print_debug(args...) printk(KERN_ERR args)
#else
#define print_debug(args...) do{} while(0)
#endif

#define print_error(args...) printk(KERN_ERR args)

#else

#if defined(DEBUG_LEVEL) && DEBUG_LEVEL > 0
#define print_debug(args...) fprintf(stderr, args)
#else
#define print_debug(args...) do{} while(0)
#endif

#define print_error(args...) fprintf(stderr, args)

#endif


#endif
