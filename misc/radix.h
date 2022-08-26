#ifndef __RADIX_H__
/*
 * radix.h
 * (C) 1996-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id: radix.h,v 1.11 2011/07/17 19:12:19 marc Exp $
 *
 */

#define __RADIX_H__
#include "misc/net.h"

struct radixtree;
typedef struct radixtree radixtree_t;

void *radix_add(radixtree_t *, struct in6_addr *, int, void *);
int radix_add_str(struct radixtree *, char *, void *);
void *radix_lookup(radixtree_t *, struct in6_addr *, void **);
void *radix_lookup_str(radixtree_t *, char *, void **);
void radix_drop(radixtree_t **, void *);
radixtree_t *radix_new(void (*)(void *, void *), int(*)(void *, void *));
void radix_walk(radixtree_t *, void (*f)(struct in6_addr *, int, void *, void *), void *);
#endif
