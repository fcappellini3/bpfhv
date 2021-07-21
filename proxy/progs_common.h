#ifndef __PROGS_COMMON_H__
#define __PROGS_COMMON_H__


#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif

#ifndef __inline
# define __inline                         \
   inline __attribute__((always_inline))
#endif


#endif
