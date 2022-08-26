/*
 * rb.h
 * (C)2000-2011 by Marc Huber <Marc.Huber@web.de>
 *
 * $Id: rb.h,v 1.13 2011/08/28 13:42:24 marc Exp marc $
 *
 */

#ifndef __RB_H__
#define __RB_H__
#include <sys/types.h>
#include "misc/sysconf.h"

struct rb_tree;
struct rb_node;
typedef struct rb_tree rb_tree_t;
typedef struct rb_node rb_node_t;

rb_tree_t *RB_tree_new(int (*)(const void *, const void *), void(*)(void *));
rb_node_t *RB_insert(rb_tree_t *, void *);
rb_node_t *RB_search(rb_tree_t *, void *);
rb_node_t *RB_first(rb_tree_t *);
rb_node_t *RB_next(rb_node_t *);
int RB_empty(rb_tree_t *);
int RB_count(rb_tree_t *);
void RB_delete(rb_tree_t *, rb_node_t *);
void RB_payload_unlink(rb_node_t *);
void RB_tree_delete(rb_tree_t *);
void RB_search_and_delete(rb_tree_t *, void *);
void *RB_lookup(rb_tree_t *, void *);
void *RB_payload_get(rb_node_t *);
#define RB_payload(A,B) ((B)RB_payload_get(A))

#endif				/* __RB_H__ */
