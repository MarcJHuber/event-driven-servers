/*
 * memops.c
 * (C) 2000-2011 Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include "misc/memops.h"
#include "mavis/log.h"

char *XXstrdup(const char *s, char *file, int line)
{
    char *a = strdup(s);
    if (!a) {
	logerr("strdup (%s:%d)", file, line);
	exit(EX_OSERR);
    }
    return a;
}

void *XXcalloc(size_t nmemb, size_t size, char *file, int line)
{
    void *a = calloc(nmemb, size);
    if (!a) {
	logerr("calloc (%s:%d)", file, line);
	exit(EX_OSERR);
    }
    return a;
}

void *XXrealloc(void *ptr, size_t size, char *file, int line)
{
    void *a = realloc(ptr, size);
    if (!a) {
	logerr("realloc (%s:%d)", file, line);
	exit(EX_OSERR);
    }
    return a;
}

static void __inline__ *mempool_attach(rb_tree_t * pool, void *p)
{
    if (pool && p)
	RB_insert(pool, p);
    return p;
}

static void *mempool_detach(rb_tree_t * pool, void *ptr)
{
    if (pool && ptr) {
	rb_node_t *rbn = RB_search(pool, ptr);
	if (rbn) {
	    RB_delete_but_keep_data(pool, rbn);
	    return ptr;
	}
    }
    return NULL;
}

void *mempool_malloc(rb_tree_t * pool, size_t size)
{
    void *p = calloc(1, size ? size : 1);

    if (p) {
	if (pool)
	    RB_insert(pool, p);
	return p;
    }
    logerr("malloc %d failure", (int) size);
    exit(EX_OSERR);
}

void mempool_free(rb_tree_t * pool, void *ptr)
{
    void **m = ptr;

    if (*m) {
	if (pool) {
	    rb_node_t *rbn = RB_search(pool, *m);
	    if (rbn) {
		RB_delete(pool, rbn);
		*m = NULL;
	    } else
		logerr("potential double-free attempt on %p", *m);
	} else {
	    free(*m);
	    *m = NULL;
	}
    }
}

static int pool_cmp(const void *a, const void *b)
{
    return (a < b) ? -1 : ((a == b) ? 0 : +1);
}

void mempool_destroy(rb_tree_t * pool)
{
    if (pool)
	RB_tree_delete(pool);
}

rb_tree_t *mempool_create(void)
{
    return RB_tree_new(pool_cmp, free);
}

char *mempool_strdup(rb_tree_t * pool, char *p)
{
    char *n = strdup(p);

    if (n) {
	if (pool)
	    RB_insert(pool, n);
	return n;
    }
    logerr("strdup allocation failure");
    exit(EX_OSERR);
}

char *mempool_strndup(rb_tree_t * pool, u_char * p, int len)
{
    char *string;
    int new_len = len;

    /* 
     * Add space for a null terminator if needed. Also, no telling
     * what various mallocs will do when asked for a length of zero.
     */
    if (!len || p[len - 1])
	new_len++;

    string = mempool_malloc(pool, new_len);

    memcpy(string, p, len);
    return string;
}

static __inline__ void *mempool_realloc(rb_tree_t * pool, void *p, size_t len)
{
    return mempool_attach(pool, realloc(mempool_detach(pool, p), len));
}

////

typedef struct {
    u_int arr_count;
    void **arr;
} memlist_t;

static memlist_t *memlist_create(void);
static void *memlist_malloc(memlist_t *, size_t);
static void *memlist_realloc(memlist_t *, void *, size_t);
static void memlist_destroy(memlist_t *);
static char *memlist_strdup(memlist_t *, char *);
static char *memlist_strndup(memlist_t *, u_char *, int);
static void memlist_add(memlist_t *, void *);

static memlist_t *memlist_create(void)
{
    return calloc(1, sizeof(memlist_t));
}

static void memlist_add(memlist_t * list, void *p)
{
    if (list && p) {
	if (!((list->arr_count) % 128))
	    list->arr = realloc(list->arr, (list->arr_count + 128) * sizeof(memlist_t));
	list->arr[list->arr_count] = p;
	list->arr_count++;
    }
}

static void *memlist_malloc(memlist_t * list, size_t size)
{
    void *p = calloc(1, size ? size : 1);

    if (list && p) {
	memlist_add(list, p);
	return p;
    }
    return p;
}

static void *memlist_realloc(memlist_t * list, void *p, size_t size)
{
    if (list && p) {
	u_int i = 0;
	for (; i < list->arr_count && list->arr[i] != p; i++);
	p = realloc(p, size);
	if (i < list->arr_count)
	    list->arr[i] = p;
	return p;
    }
    return memlist_malloc(list, size);
}

static void memlist_destroy(memlist_t * list)
{
    for (u_int i = 0; i < list->arr_count; i++)
	if (list->arr[i])
	    free(list->arr[i]);
    free(list->arr);
    free(list);
}

static char *memlist_strdup(memlist_t * list, char *s)
{
    char *p = strdup(s);
    if (list)
	memlist_add(list, p);
    return p;
}

static char *memlist_strndup(memlist_t * list, u_char * s, int len)
{
    char *p = strndup((char *) s, len);
    if (list)
	memlist_add(list, p);
    return p;
}

static void memlist_free(memlist_t * list, void *ptr)
{
    void **m = ptr;
    if (list && *m)
	for (u_int i = 0; i < list->arr_count; i++)
	    if (list->arr[i] == *m) {
		free(*m);
		*m = NULL;
		list->arr_count--;
		if (list->arr_count > 0)
		    list->arr[i] = list->arr[list->arr_count];
		return;
	    }
}

static void __inline__ *memlist_attach(memlist_t * list, void *p)
{
    if (list && p)
	memlist_add(list, p);
    return p;
}

static void *memlist_detach(memlist_t * list, void *ptr)
{
    if (list && ptr)
	for (u_int i = 0; i < list->arr_count; i++)
	    if (list->arr[i] == ptr) {
		list->arr_count--;
		if (list->arr_count > 0)
		    list->arr[i] = list->arr[list->arr_count];
		return ptr;
	    }
    return NULL;
}

//

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
    u_int arr_count;
    struct mem_free_s *arr;
};

mem_t *mem_create(enum mem_type type)
{
    if (type) {
	mem_t *m = calloc(1, sizeof(struct mem));
	m->type = type;
	if (type == M_LIST)
	    m->u.list = memlist_create();
	else if (type == M_POOL)
	    m->u.pool = mempool_create();
	return m;
    }
    return NULL;
}

void *mem_alloc(mem_t * m, size_t size)
{
    if (m) {
	if (m->type == M_LIST)
	    return memlist_malloc(m->u.list, size);
	if (m->type == M_POOL)
	    return mempool_malloc(m->u.pool, size);
    }
    return calloc(1, size);
}

void *mem_destroy(mem_t * m)
{
    if (m) {
	if (m->type == M_LIST)
	    memlist_destroy(m->u.list);
	else if (m->type == M_POOL)
	    mempool_destroy(m->u.pool);
	for (u_int i = 0; i < m->arr_count; i++)
	    m->arr[i].f(m->arr[i].p);
	if (m->arr)
	    free(m->arr);
	free(m);
    }
    return NULL;
}

void *mem_free(mem_t * m, void *ptr)
{
    void **p = ptr;
    if (*p) {
	if (m) {
	    if (m->type == M_POOL)
		mempool_free(m->u.pool, ptr);
	    else if (m->type == M_LIST)
		memlist_free(m->u.list, ptr);
	} else
	    free(*p);
	*p = NULL;
    }
    return NULL;
}

char *mem_strdup(mem_t * m, char *s)
{
    if (m) {
	if (m->type == M_LIST)
	    return memlist_strdup(m->u.list, s);
	if (m->type == M_POOL)
	    return mempool_strdup(m->u.pool, s);
    }
    return strdup(s);
}

char *mem_strndup(mem_t * m, u_char * s, size_t len)
{
    if (m) {
	if (m->type == M_LIST)
	    return memlist_strndup(m->u.list, s, len);
	if (m->type == M_POOL)
	    return mempool_strndup(m->u.pool, s, len);
    }
    return strndup((char *) s, len);
}

void *mem_realloc(mem_t * m, void *p, size_t len)
{
    if (m) {
	if (m->type == M_LIST)
	    return memlist_realloc(m->u.list, p, len);
	if (m->type == M_POOL)
	    return mempool_realloc(m->u.pool, p, len);
    }
    return realloc(p, len);
}

void *mem_copy(mem_t * m, void *p, size_t len)
{
    void *b = malloc(len + 1);
    memcpy(b, p, len);
    ((char *) b)[len] = 0;
    return mem_attach(m, b);
}

void mem_add_free(mem_t * m, void *freefun, void *p)
{
    if (m) {
	if (!(m->arr_count % 16))
	    m->arr = realloc(m->arr, sizeof(struct mem_free_s) * (m->arr_count + 16));
	m->arr[m->arr_count].f = freefun;
	m->arr[m->arr_count].p = p;
	m->arr_count++;
    }
}

void *mem_attach(mem_t * m, void *p)
{
    if (m && p) {
	if (m->type == M_LIST)
	    return memlist_attach(m->u.list, p);
	if (m->type == M_POOL)
	    return mempool_attach(m->u.pool, p);
    }
    return p;
}

void *mem_detach(mem_t * m, void *p)
{
    if (m && p) {
	if (m->type == M_LIST)
	    return memlist_detach(m->u.list, p);
	if (m->type == M_POOL)
	    return mempool_detach(m->u.pool, p);
    }
    return p;
}
