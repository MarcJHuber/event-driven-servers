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
#include "misc/rb.h"
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

enum mem_type { M_STD = 0, M_LIST, M_POOL };

struct mem;
typedef struct mem mem_t;

struct mem *mem_create(enum mem_type type);
void *mem_destroy(mem_t * m);
void *mem_alloc(mem_t * m, size_t size);
char *mem_strdup(mem_t * m, char *s);
char *mem_strndup(mem_t * m, u_char * s, size_t len);
void *mem_realloc(mem_t * m, void *p, size_t len);
void *mem_copy(mem_t * m, void *p, size_t len);
void *mem_free(mem_t * m, void *p);
void *mem_attach(mem_t *, void *);
void *mem_detach(mem_t * m, void *p);
void mem_add_free(mem_t * m, void *, void *);

#endif				/* __MEMOPS_H__ */
