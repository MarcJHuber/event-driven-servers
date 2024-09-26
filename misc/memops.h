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

struct memlist;
typedef struct memlist memlist_t;

struct mem_free_s {
    void (*f)(void *);
    void *p;
};

struct mem {
    union {
	memlist_t *list;
	rb_tree_t *pool;
    } u;
    enum mem_type type;
    u_int arr_len;
    struct mem_free_s *arr;
};

typedef struct mem mem_t;

struct mem *mem_create(enum mem_type type);
void *mem_alloc(struct mem *m, size_t size);
void *mem_destroy(struct mem *m);
void *mem_free(struct mem *m, void *p);
char *mem_strdup(struct mem *m, char *s);
char *mem_strndup(struct mem *m, u_char * s, size_t len);
void *mem_realloc(struct mem *m, void *p, size_t len);
void *mem_copy(struct mem *m, void *p, size_t len);
void mem_add_free(struct mem *m, void *, void *);

void *mempool_malloc(rb_tree_t *, size_t);
void *mempool_realloc(rb_tree_t *, void *, size_t);
void mempool_free(rb_tree_t *, void *);
char *mempool_strdup(rb_tree_t *, char *);
char *mempool_strndup(rb_tree_t *, u_char *, int);
void mempool_destroy(rb_tree_t *);
rb_tree_t *mempool_create(void);

struct memlist *memlist_create(void);
void *memlist_malloc(memlist_t *, size_t);
void *memlist_realloc(memlist_t *, void *, size_t);
void memlist_destroy(memlist_t *);
char *memlist_strdup(memlist_t *, char *);
char *memlist_strndup(memlist_t *, u_char *, int);
void **memlist_add(memlist_t *, void *);
char *memlist_attach(memlist_t *, void *);
void *mempool_detach(rb_tree_t *, void *);
char *memlist_copy(memlist_t *, void *, size_t);
#endif				/* __MEMOPS_H__ */
