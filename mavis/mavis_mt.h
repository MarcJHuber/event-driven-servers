/*
 * mavis_mt.h
 * The thread stack of the -mt backends.
 */

#ifndef __MAVIS_MT_H_
#define __MAVIS_MT_H_
#include <pthread.h>

// A worker thread keeps the complete reply on its stack. The default of musl is 128 KB.
#define STACKSIZE_MAVIS_MT (8 * 1024 * 1024)

static __inline__ int mavis_mt_raise_stack(pthread_attr_t *attr)
{
    size_t size = 0;
    int res = pthread_attr_getstacksize(attr, &size);
    if (!res && size < STACKSIZE_MAVIS_MT)
	res = pthread_attr_setstacksize(attr, STACKSIZE_MAVIS_MT);
    return res;
}
#endif
