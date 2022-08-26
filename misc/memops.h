/*
 * memops.h
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 *
 * $Id: memops.h,v 1.10 2011/07/17 19:12:19 marc Exp $
 *
 */

#ifndef __MEMOPS_H__
#define __MEMOPS_H__

#include "misc/sysconf.h"
#include <sysexits.h>
#include <stdlib.h>

#define Xcalloc(A,B) XXcalloc((size_t)(A), B, __FILE__, __LINE__)
#define Xrealloc(A,B) XXrealloc(A, (size_t)(B), __FILE__, __LINE__)
#define Xstrdup(A) XXstrdup(A, __FILE__, __LINE__)

char *XXstrdup(const char *, char *, int);
void *XXcalloc(size_t, size_t, char *, int);
void *XXrealloc(void *, size_t, char *, int);

static __inline__ void Xfree(void *pa)
{
    void **m = pa;
    if (*m) {
	free(*m);
	*m = NULL;
    }
}

#endif				/* __MEMOPS_H__ */
