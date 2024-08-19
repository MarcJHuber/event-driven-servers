/*
 * rb.h
 * (C)2000-2011 by Marc Huber <Marc.Huber@web.de>
 *
 * $Id: rb.h,v 1.13 2011/08/28 13:42:24 marc Exp marc $
 *
 */

#ifndef __RB_H__
#define __RB_H__
#include <stdlib.h>
#include <sys/types.h>
#include "misc/sysconf.h"
#include "misc/rbtree.h"

#define rb_node_t rbnode_type
#define rb_tree_t rbtree_type

inline __attribute__((always_inline)) rbtree_type *RB_tree_new(int (*cmpf)(const void *, const void *), void(*freef)(void *)) 
{
	return rbtree_create(cmpf, (const void *) freef);
}

inline __attribute__((always_inline)) rbnode_type *RB_insert(rbtree_type *rbtree, void *data) 
{
	rbnode_type *rbnode = calloc(1, sizeof(rbnode_type));
	rbnode->key = data;
	rbnode_type *rbnode_out = rbtree_insert(rbtree, rbnode);
	if (rbnode_out)
		return rbnode_out;
	free(rbnode);
	return NULL;
}

inline __attribute__((always_inline)) rbnode_type *RB_search(rbtree_type *rbtree, void *key) 
{
	return rbtree_search(rbtree, key);
}

inline __attribute__((always_inline)) rbnode_type *RB_first(rbtree_type *rbtree) 
{
	return rbtree_first(rbtree);
}

inline __attribute__((always_inline)) rbnode_type *RB_next(rbnode_type *rbnode) 
{
	return rbtree_next(rbnode);
}

inline __attribute__((always_inline)) int RB_empty(rbtree_type *rbtree) 
{
	return rbtree ? (rbtree->count == 0) : -1;
}

inline __attribute__((always_inline)) int RB_count(rbtree_type *rbtree) 
{
	return rbtree ? rbtree->count : 0;
}

void rbtree_freefunc(rbnode_type *rbnode, void *data);

inline __attribute__((always_inline)) void RB_delete(rbtree_type *rbtree, rbnode_type *rbnode) 
{
	rbtree_delete_node(rbtree, rbnode);
	if (rbtree->free)
		rbtree->free((void *) rbnode->key);
	free(rbnode);
}

inline __attribute__((always_inline)) const void *RB_delete_but_keep_data(rbtree_type *rbtree, rbnode_type *rbnode) 
{
	rbtree_delete_node(rbtree, rbnode);
	const void *ptr = rbnode->key;
	free(rbnode);
	return ptr;
}

inline __attribute__((always_inline)) void RB_tree_delete(rbtree_type *rbtree) 
{
	if (rbtree) {
		traverse_postorder(rbtree, rbtree_freefunc, rbtree);
		free(rbtree);
	}
}

inline __attribute__((always_inline)) void RB_search_and_delete(rbtree_type *rbtree, void *data) 
{
	rbnode_type *rbnode = rbtree_delete(rbtree, data);
	if (rbnode) {
		if (rbtree->free)
			rbtree->free((void *) rbnode->key);
		free(rbnode);
	}
}

inline __attribute__((always_inline)) void *RB_lookup(rbtree_type *rbtree, void *data) 
{
	rbnode_type *rbnode = rbtree_search(rbtree, data);
	return rbnode ? (void *) rbnode->key : NULL;
}

inline __attribute__((always_inline)) void *RB_payload_get(rbnode_type *rbnode) 
{
	return (void *) rbnode->key;
}
#define RB_payload(A,B) ((B)RB_payload_get(A))


#endif				/* __RB_H__ */
