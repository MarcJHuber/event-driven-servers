/*
 * radix.c
 * (C) 1996-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "misc/memops.h"
#include "misc/net.h"
#include "misc/radix.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

struct radixnode {
    struct radixnode *l;	/* left */
    struct radixnode *r;	/* right */
    u_int m:8;			/* cidr mask len 0..128 */
    u_int i:1;			/* infrastructure flag */
    struct in6_addr a;		/* IPv6 base address, host byte order */
    void *d;			/* data */
};

struct radixnode_array {
#define RADIX_ARRSIZE 1024
    struct radixnode array[RADIX_ARRSIZE];
    struct radixnode_array *next;
};

struct radixtree {
    struct radixnode *root;
    void (*free)(void * /* payload */ , void * /* data */ );
    int (*cmp)(void * /* payload 1 */ , void * /* payload 2 */ );
    uint64_t (*payload_hash)(const void *);
    uint64_t fingerprint;
    unsigned int refs;
};

static int radixtree_count = 0;
static struct radixnode_array *radix_nodes = NULL;
static struct radixnode *nextfree = NULL;

static struct radixnode *radixnode_alloc(void)
{
    if (!nextfree) {
	struct radixnode_array *a = Xcalloc(1, sizeof(struct radixnode_array));
	a->next = radix_nodes;
	radix_nodes = a;
	for (int i = 0; i < RADIX_ARRSIZE - 1; i++)
	    a->array[i].l = &a->array[i + 1];
	nextfree = &a->array[0];
    }
    struct radixnode *n = nextfree;
    nextfree = nextfree->l;
    memset(n, 0, sizeof(struct radixnode));
    return n;
}

static void radixnode_free(struct radixnode *n)
{
    n->l = nextfree;
    nextfree = n;
}

#define v6_bitset(a,b) ((b > 0) && ((b) < 129) && \
	((a).s6_addr32[(b-1)>>5] & (0x80000000 >> ((b-1)&0x1f))))

static uint64_t mix64(uint64_t x)
{
    x ^= x >> 30;
    x *= UINT64_C(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x *= UINT64_C(0x94d049bb133111eb);
    return x ^ (x >> 31);
}

static void radix_fingerprint_add(struct radixtree *rt, const struct in6_addr *a, int m, const void *d)
{
    uint64_t lo, hi;
    memcpy(&lo, a, sizeof(lo));
    memcpy(&hi, (const unsigned char *) a + sizeof(lo), sizeof(hi));
    uint64_t payload = rt->payload_hash ? rt->payload_hash(d) : (uint64_t) (uintptr_t) d;
    rt->fingerprint += mix64(lo ^ mix64(hi) ^ mix64(payload) ^ (uint64_t) m);
}

void *radix_add(struct radixtree *rt, struct in6_addr *a, int m, void *d)
{
    struct radixnode *r, *n, **rp;

    v6_network(a, a, m);

    if (!rt->root) {
	rt->root = radixnode_alloc();
	rt->root->a = *a, rt->root->m = m, rt->root->d = d;
	radix_fingerprint_add(rt, a, m, d);
	return NULL;
    }

    r = rt->root;

    while (1) {
	if (!v6_cmp(&r->a, a) && (r->m == m)) {
	    /* new node identical to current root */
	    if (r->i) {
		r->i = 0, r->d = d;
		radix_fingerprint_add(rt, a, m, d);
		return NULL;
	    }
	    /* node already defined, but succeed if identical payload */
	    if (r->d == d)
		return NULL;
	    if (rt->cmp)
		return rt->cmp(r->d, d) ? r->d : NULL;
	    return r->d;
	}
	if (m < r->m && v6_contains(a, m, &r->a)) {
	    /* current root is subnode of new node */
	    struct radixnode *nr = radixnode_alloc();
	    *nr = *r;
	    if (v6_bitset(r->a, m + 1))
		r->r = nr, r->l = NULL;
	    else
		r->l = nr, r->r = NULL;
	    r->a = *a, r->d = d, r->m = m, r->i = 0;
	    radix_fingerprint_add(rt, a, m, d);
	    return NULL;
	}

	if (r->m < m && v6_contains(&r->a, r->m, a)) {
	    /* new node is subnode of current root */
	    if (v6_bitset(*a, r->m + 1)) {
		if (r->r) {
		    r = r->r;
		    continue;
		}
		rp = &r->r;
	    } else {
		if (r->l) {
		    r = r->l;
		    continue;
		}
		rp = &r->l;
	    }
	} else {
	    /* infrastructural root required */
	    n = radixnode_alloc();
	    *n = *r;
	    r->m = v6_common_cidr(&r->a, a, r->m < m ? r->m : m);
	    r->i = 1, r->d = NULL;
	    v6_network(&r->a, &r->a, r->m);

	    if (v6_bitset(*a, r->m + 1))
		r->l = n, rp = &r->r;
	    else
		r->r = n, rp = &r->l;
	}

	*rp = radixnode_alloc();
	(*rp)->a = *a, (*rp)->d = d, (*rp)->m = m;
	radix_fingerprint_add(rt, a, m, d);
	return NULL;
    }
}

void *radix_lookup(struct radixtree *rt, struct in6_addr *a, void **arr)
{
    void *match = NULL;

    if (rt) {
	struct radixnode *rn = rt->root;
	while (rn) {
	    int bit;
	    struct in6_addr a2;

	    v6_network(&a2, a, rn->m);
	    if (v6_cmp(&rn->a, &a2))
		return match;

	    if (!rn->i)
		match = rn->d;

	    if (arr && rn->d) {
		*arr = rn->d;
		arr++;
	    }

	    bit = v6_bitset(*a, rn->m + 1);

	    if (rn->r && bit)
		rn = rn->r;
	    else if (rn->l && !bit)
		rn = rn->l;
	    else
		return match;
	}
    }
    return match;
}

static void radix_dropnode(struct radixtree *rt, struct radixnode *rn, void *data)
{
    if (rn) {
	radix_dropnode(rt, rn->l, data);
	radix_dropnode(rt, rn->r, data);
	if (rt->free)
	    rt->free(rn->d, data);
	radixnode_free(rn);
    }
}

void radix_drop(struct radixtree **rt, void *data)
{
    if (*rt) {
	struct radixtree *r = *rt;
	*rt = NULL;
	if (--r->refs)
	    return;
	radix_dropnode(r, r->root, data);
	free(r);
	if (!--radixtree_count) {
	    while (radix_nodes) {
		struct radixnode_array *a = radix_nodes->next;
		free(radix_nodes);
		radix_nodes = a;
	    }
	}
    }
}

struct radixtree *radix_new(void (*f)(void *, void *), int(*c)(void *, void *))
{
    struct radixtree *rt = Xcalloc(1, sizeof(struct radixtree));
    rt->free = f;
    rt->cmp = c;
    rt->refs = 1;
    radixtree_count++;
    return rt;
}

void radix_retain(struct radixtree *rt)
{
    if (rt)
	rt->refs++;
}

void radix_set_payload_hash(struct radixtree *rt, uint64_t (*payload_hash)(const void *))
{
    if (rt)
	rt->payload_hash = payload_hash;
}

uint64_t radix_fingerprint(struct radixtree *rt)
{
    return rt ? rt->fingerprint : 0;
}

static int radix_equalnode(struct radixnode *a, struct radixnode *b, int (*payload_equal)(const void *, const void *))
{
    if (!a || !b)
	return a == b;
    if (a->m != b->m || a->i != b->i || v6_cmp(&a->a, &b->a))
	return 0;
    if (!a->i && payload_equal && !payload_equal(a->d, b->d))
	return 0;
    return radix_equalnode(a->l, b->l, payload_equal) && radix_equalnode(a->r, b->r, payload_equal);
}

int radix_equal(struct radixtree *a, struct radixtree *b, int (*payload_equal)(const void *, const void *))
{
    if (a == b)
	return 1;
    if (!a || !b)
	return 0;
    return radix_equalnode(a->root, b->root, payload_equal);
}

static void radix_walknode(struct radixnode *rn, void (*f)(struct in6_addr *, int, void *, void *), void *data)
{
    if(rn) {
	radix_walknode(rn->l, f, data);
	radix_walknode(rn->r, f, data);
	if (!rn->i)
	    f(&rn->a, rn->m, rn->d, data);
    }
}

void radix_walk(struct radixtree *rt, void (*f)(struct in6_addr *, int, void *, void *), void *data)
{
    radix_walknode(rt->root, f, data);
}

int radix_add_str(struct radixtree *rt, char *cidr, void *payload)
{
    struct in6_addr a;
    int cm;

    if (v6_ptoh(&a, &cm, cidr))
	return -1;
    if (radix_add(rt, &a, cm, payload))
	return +1;
    return 0;
}

void *radix_lookup_str(struct radixtree *rt, char *addr, void **arr)
{
    struct in6_addr a;

    return v6_ptoh(&a, NULL, addr) ? NULL : radix_lookup(rt, &a, arr);
}
