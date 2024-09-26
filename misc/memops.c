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


struct memlist {
    u_int count;
    memlist_t *next;
#define MEMLIST_ARR_SIZE 128
    void *arr[MEMLIST_ARR_SIZE];
};

struct memlist *memlist_create(void)
{
    return calloc(1, sizeof(memlist_t));
}

void **memlist_add(memlist_t * list, void *p)
{
    void **res = NULL;
    if (p && list) {
	while (list->count == MEMLIST_ARR_SIZE && list->next)
	    list = list->next;
	if (list->count == MEMLIST_ARR_SIZE) {
	    list->next = memlist_create();
	    list = list->next;
	}
	list->arr[list->count] = p;
	res = &list->arr[list->count];
	list->count++;
    }
    return res;
}

void *memlist_malloc(memlist_t * list, size_t size)
{
    void *p = calloc(1, size ? size : 1);

    if (p) {
	memlist_add(list, p);
	return p;
    }
    logerr("malloc %d failure", (int) size);
    exit(EX_OSERR);
}

void *memlist_realloc(memlist_t * list, void *p, size_t size)
{
    if (p) {
	u_int i = 0;
	while (list && i < list->count) {
	    if (list->arr[i] == p)
		break;
	    i++;
	    if (i == MEMLIST_ARR_SIZE) {
		i = 0;
		list = list->next;
	    }
	}
	p = realloc(p, size);
	if (list && i < list->count)
	    list->arr[i] = p;
	else {
	    logerr("realloc %d failure", (int) size);
	    exit(EX_OSERR);
	}
	return p;
    }
    return memlist_malloc(list, size);
}

void memlist_destroy(memlist_t * list)
{
    while (list) {
	u_int i;
	memlist_t *next = NULL;
	for (i = 0; i < list->count; i++)
	    if (list->arr[i])
		free(list->arr[i]);
	next = list->next;
	free(list);
	list = next;
    }
}

char *memlist_strdup(memlist_t * list, char *s)
{
    char *p = strdup(s);

    if (p) {
	memlist_add(list, p);
	return p;
    }
    logerr("strdup failure");
    exit(EX_OSERR);
}

char *memlist_strndup(memlist_t * list, u_char * s, int len)
{
    char *p = strndup((char *) s, len);

    if (p) {
	memlist_add(list, p);
	return p;
    }
    logerr("strndup failure");
    exit(EX_OSERR);
}

char *memlist_attach(memlist_t * list, void *p)
{
    if (p)
	memlist_add(list, p);
    return p;
}

void *mempool_detach(rb_tree_t * pool, void *ptr)
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

char *memlist_copy(memlist_t * list, void *s, size_t len)
{
    char *p = NULL;
    if (s) {
	p = memlist_malloc(list, len + 1);
	memcpy(p, s, len);
	p[len] = 0;
    }
    return p;
}

char *mempool_copy(rb_tree_t * pool, void *s, size_t len)
{
    char *p = NULL;
    if (s) {
	p = mempool_malloc(pool, len + 1);
	memcpy(p, s, len);
	p[len] = 0;
    }
    return p;
}

//
struct mem *mem_create(enum mem_type type)
{
    if (type) {
	struct mem *m = calloc(1, sizeof(struct mem));
	m->type = type;
	if (type == M_LIST)
	    m->u.list = memlist_create();
	else if (type == M_POOL)
	    m->u.pool = mempool_create();
	return m;
    }
    return NULL;
}

void *mem_alloc(struct mem *m, size_t size)
{
    if (m) {
	if (m->type == M_LIST)
	    return memlist_malloc(m->u.list, size);
	if (m->type == M_POOL)
	    return mempool_malloc(m->u.pool, size);
    }
    return calloc(1, size);
}

void *mem_destroy(struct mem *m)
{
    if (m) {
	if (m->type == M_LIST)
	    memlist_destroy(m->u.list);
	else if (m->type == M_POOL)
	    mempool_destroy(m->u.pool);
	for (u_int i = 0; i < m->arr_len; i++)
	    m->arr[i].f(m->arr[i].p);
	if (m->arr)
	    free(m->arr);
	free(m);
    }
    return NULL;
}

void *mem_free(struct mem *m, void *ptr)
{
    void **p = ptr;
    if (*p) {
	if (m) {
	    if (m->type == M_POOL)
		mempool_free(m->u.pool, ptr);
	} else
	    free(*p);
	*p = NULL;
    }
    return NULL;
}

char *mem_strdup(struct mem *m, char *s)
{
    if (m) {
	if (m->type == M_LIST)
	    return memlist_strdup(m->u.list, s);
	if (m->type == M_POOL)
	    return mempool_strdup(m->u.pool, s);
    }
    return strdup(s);
}

char *mem_strndup(struct mem *m, u_char * s, size_t len)
{
    if (m) {
	if (m->type == M_LIST)
	    return memlist_strndup(m->u.list, s, len);
	if (m->type == M_POOL)
	    return mempool_strndup(m->u.pool, s, len);
    }
    return strndup((char *) s, len);
}

void *mem_realloc(struct mem *m, void *p, size_t len)
{
    if (m) {
	if (m->type == M_LIST)
	    return memlist_realloc(m->u.list, p, len);
	if (m->type == M_POOL)
	    fprintf(stderr, "%s is unsupported for M_POOL", __func__);
    }
    return realloc(p, len);
}

void *mem_copy(struct mem *m, void *p, size_t len)
{
    if (m) {
	if (m->type == M_LIST)
	    return memlist_copy(m->u.list, p, len);
	if (m->type == M_POOL)
	    return mempool_copy(m->u.pool, p, len);
    }
    if (!len)
	len++;
    void *b = malloc(len);
    memcpy(b, p, len);
    return b;
}

void mem_add_free(struct mem *m, void *freefun, void *p)
{
    if (m) {
	m->arr = realloc(m->arr, sizeof(struct mem_free_s) * (m->arr_len + 1));
	m->arr[m->arr_len].f = freefun;
	m->arr[m->arr_len].p = p;
	m->arr_len++;
    }
}
