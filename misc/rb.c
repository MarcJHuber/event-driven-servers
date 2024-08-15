/*
 * rb.c
 * (C)2000-2011 by Marc Huber <Marc.Huber@web.de>
 *
 * The RB routines are quite heavily based on sample code published in:
 *
 *   Introduction to Algorithms
 *     Chapter 14: Red-Black Trees
 *   Authors: Thomas H. Cormen, Charles E. Leiserson, Ronald L. Rivest
 *   ISBN 0-262-0314108 (MIT Press)
 *   ISBN 0-07-013143-0 (McGraw-Hill)
 *
 *
 * $Id$
 *
 */

#include "misc/sysconf.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include "misc/memops.h"
#include "misc/rb.h"
#define BLACK 0
#define RED 1

struct rb_node {
    void *payload;
    rb_node_t *left;
    rb_node_t *right;
    rb_node_t *prev;
    rb_node_t *next;
    rb_node_t *parent;
    u_int color:1;
};

struct rb_nodearray {
#define RB_ARRSIZE 1024
    rb_node_t array[RB_ARRSIZE];
    struct rb_nodearray *next;
};

struct rb_tree {
    int count;
    rb_node_t *root;
    rb_node_t *first;
    int (*compare)(const void *, const void *);
    void (*free)(void *);
};

static rb_node_t *rb_nil = NULL;
static int rb_tree_count = 0;
static struct rb_nodearray *rb_nodes = NULL;
static rb_node_t *nextfree = NULL;

static rb_node_t *rb_alloc(void)
{
    rb_node_t *n;
#ifdef DEBUG_RB
    rb_count++;
#endif
    if (!nextfree) {
	struct rb_nodearray *a = Xcalloc(1, sizeof(struct rb_nodearray));
	int i;
	a->next = rb_nodes;
	rb_nodes = a;
	for (i = 0; i < RB_ARRSIZE - 1; i++)
	    a->array[i].next = &a->array[i + 1];
	nextfree = &a->array[0];
    }
    n = nextfree;
    nextfree = nextfree->next;
    n->left = rb_nil;
    n->right = rb_nil;
    n->parent = rb_nil;
    n->prev = rb_nil;
    n->next = rb_nil;
#ifdef DEBUG_RB
    fprintf(stderr, "rb_alloc: %p (%d in use)\n", n, rb_count);
#endif
    return n;
}

static void rb_free(rb_node_t * n)
{
#ifdef DEBUG_RB
    rb_count--;
    fprintf(stderr, "rb_free: %p (%d in use)\n", n, rb_count);
#endif
    memset(n, 0, sizeof(rb_node_t));
    n->next = nextfree;
    nextfree = n;
}

static rb_node_t *tree_minimum(rb_node_t * x)
{
    while (x->left != rb_nil)
	x = x->left;
    return x;
}

static rb_node_t *tree_maximum(rb_node_t * x)
{
    while (x->right != rb_nil)
	x = x->right;
    return x;
}

static rb_node_t *tree_successor(rb_node_t * x)
{
    rb_node_t *y;

    if (x->right != rb_nil)
	return tree_minimum(x->right);
    y = x->parent;
    while (y != rb_nil && x == y->right) {
	x = y;
	y = y->parent;
    }
    return y;
}

static rb_node_t *tree_predecessor(rb_node_t * x)
{
    rb_node_t *y;

    if (x->left != rb_nil)
	return tree_maximum(x->left);
    y = x->parent;
    while (y != rb_nil && x == y->left) {
	x = y;
	y = y->parent;
    }
    return y;
}

static void left_rotate(rb_tree_t * T, rb_node_t * x)
{
    rb_node_t *y;

    y = x->right;
    x->right = y->left;
    if (y->left != rb_nil)
	y->left->parent = x;
    y->parent = x->parent;
    if (x->parent == rb_nil)
	T->root = y;
    else {
	if (x == x->parent->left)
	    x->parent->left = y;
	else
	    x->parent->right = y;
    }
    y->left = x;
    x->parent = y;
}

static void right_rotate(rb_tree_t * T, rb_node_t * x)
{
    rb_node_t *y;

    y = x->left;
    x->left = y->right;
    if (y->right != rb_nil)
	y->right->parent = x;
    y->parent = x->parent;
    if (x->parent == rb_nil)
	T->root = y;
    else {
	if (x == x->parent->right)
	    x->parent->right = y;
	else
	    x->parent->left = y;
    }
    y->right = x;
    x->parent = y;
}

static int tree_insert(rb_tree_t * T, rb_node_t * z)
{
    rb_node_t *x, *y;
    int i = 0;
    y = rb_nil;
    x = T->root;
    while (x != rb_nil) {
	y = x;
	i = T->compare(z->payload, x->payload);
	if (i < 0)
	    x = x->left;
	else if (i > 0)
	    x = x->right;
	else {
#ifdef DEBUG_RB
	    fprintf(stderr, "dupe! %p\n", z->payload);
#endif
	    return 0;		/* Duplicate! */
	}
    }
    z->parent = y;
    if (y == rb_nil)
	T->root = z;
    else if (i < 0)
	y->left = z;
    else
	y->right = z;
    z->prev = tree_predecessor(z);
    if (z->prev != rb_nil) {
	z->next = z->prev->next;
	z->prev->next = z;
	if (z->next != rb_nil)
	    z->next->prev = z;
    } else {
	T->first = z;
	z->next = tree_successor(z);
	if (z->next != rb_nil)
	    z->next->prev = z;
    }
    T->count++;
    return -1;
}

rb_tree_t *RB_tree_new(int (*compare)(const void *, const void *), void (*freenode)(void *))
{
    rb_tree_t *T = Xcalloc(1, sizeof(rb_tree_t));
#ifdef DEBUG_RB
    fprintf(stderr, "RB_tree_new = %p\n", T);
#endif
    if (!rb_nil) {
	rb_nil = rb_alloc();
#ifdef DEBUG_RB
	fprintf(stderr, "rb_nil = %p\n", rb_nil);
#endif
	rb_nil->color = BLACK;
	rb_nil->payload = NULL;
    }
    rb_tree_count++;

    if (compare)
	T->compare = compare;
    else
	T->compare = (int (*)(const void *, const void *)) strcmp;
    T->free = freenode;
    T->root = T->first = rb_nil;
    return T;
}

static int rb_insert(rb_tree_t * T, rb_node_t * x)
{
    rb_node_t *y;

    if (!tree_insert(T, x))
	return 0;

    x->color = RED;
    while (x != T->root && x->parent->color == RED) {
	if (x->parent == x->parent->parent->left) {
	    y = x->parent->parent->right;
	    if (y->color == RED) {
		x->parent->color = BLACK;
		y->color = BLACK;
		x->parent->parent->color = RED;
		x = x->parent->parent;
	    } else {
		if (x == x->parent->right) {
		    x = x->parent;
		    left_rotate(T, x);
		}
		x->parent->color = BLACK;
		x->parent->parent->color = RED;
		right_rotate(T, x->parent->parent);
	    }
	} else {
	    y = x->parent->parent->left;
	    if (y->color == RED) {
		x->parent->color = BLACK;
		y->color = BLACK;
		x->parent->parent->color = RED;
		x = x->parent->parent;
	    } else {
		if (x == x->parent->left) {
		    x = x->parent;
		    right_rotate(T, x);
		}
		x->parent->color = BLACK;
		x->parent->parent->color = RED;
		left_rotate(T, x->parent->parent);
	    }
	}
    }
    T->root->color = BLACK;
    return -1;
}

rb_node_t *RB_insert(rb_tree_t * T, void *payload)
{
    rb_node_t *x = rb_alloc();
#ifdef DEBUG_RB
    fprintf(stderr, "RB_insert(%p, %p)\n", T, x);
#endif
    x->payload = payload;
    if (!rb_insert(T, x)) {
	rb_free(x);
	return NULL;
    }
    return x;
}

static void rb_delete_fixup(rb_tree_t * T, rb_node_t * x)
{
    while (x != T->root && x->color == BLACK) {
	if (x == x->parent->left) {
	    rb_node_t *w;
	    w = x->parent->right;
	    if (w->color == RED) {
		w->color = BLACK;
		x->parent->color = RED;
		left_rotate(T, x->parent);
		w = x->parent->right;
	    }
	    if (w->left->color == BLACK && w->right->color == BLACK) {
		w->color = RED;
		x = x->parent;
	    } else {
		if (w->right->color == BLACK) {
		    w->left->color = BLACK;
		    w->color = RED;
		    right_rotate(T, w);
		    w = x->parent->right;
		}
		w->color = x->parent->color;
		x->parent->color = BLACK;
		w->right->color = BLACK;
		left_rotate(T, x->parent);
		x = T->root;
	    }
	} else {
	    rb_node_t *w;
	    w = x->parent->left;
	    if (w->color == RED) {
		w->color = BLACK;
		x->parent->color = RED;
		right_rotate(T, x->parent);
		w = x->parent->left;
	    }
	    if (w->right->color == BLACK && w->left->color == BLACK) {
		w->color = RED;
		x = x->parent;
	    } else {
		if (w->left->color == BLACK) {
		    w->right->color = BLACK;
		    w->color = RED;
		    left_rotate(T, w);
		    w = x->parent->left;
		}
		w->color = x->parent->color;
		x->parent->color = BLACK;
		w->left->color = BLACK;
		right_rotate(T, x->parent);
		x = T->root;
	    }
	}
    }
    x->color = BLACK;
}

void RB_delete(rb_tree_t * T, rb_node_t * z)
{
    rb_node_t *x, *y;

#ifdef DEBUG_RB
    fprintf(stderr, "RB_delete(%p, %p)\n", T, z);
#endif

    if (z->left == rb_nil || z->right == rb_nil)
	y = z;
    else
	y = z->prev;

    if (y->left != rb_nil)
	x = y->left;
    else
	x = y->right;
    x->parent = y->parent;
    if (y->parent == rb_nil)
	T->root = x;
    else {
	if (y == y->parent->left)
	    y->parent->left = x;
	else
	    y->parent->right = x;
    }
    if (y != z) {
	if (T->free && z->payload)
	    T->free(z->payload);
	z->payload = y->payload;
	y->payload = NULL;
    }
    if (y->color == BLACK)
	rb_delete_fixup(T, x);

    if (y->next != rb_nil)
	y->next->prev = y->prev;
    if (y->prev != rb_nil)
	y->prev->next = y->next;
    else
	T->first = y->next;
    if (T->free && y->payload)
	T->free(y->payload);
    rb_free(y);
    T->count--;
}

rb_node_t *RB_search(rb_tree_t * T, void *payload)
{
    rb_node_t *x = T->root;
    int count = 0;

    while (x != rb_nil) {
	int i = T->compare(payload, x->payload);
#if 1				//#ifdef DEBUG_RB
	if (count++ > T->count) {
	    fprintf(stderr, "RB_search: possible loop detected, returning NULL\n");
	    return NULL;
	}
#endif

	if (i < 0)
	    x = x->left;
	else if (i > 0)
	    x = x->right;
	else
	    return x;
    }
    return NULL;
}

rb_node_t *RB_first(rb_tree_t * T)
{
    if (T && T->first != rb_nil)
	return T->first;
    return NULL;
}

rb_node_t *RB_next(rb_node_t * z)
{
    if (z && z->next != rb_nil)
	return z->next;
    return NULL;
}

static void rb_tree_delete(rb_tree_t * T, rb_node_t * z)
{
#ifdef DEBUG_RB
    fprintf(stderr, "# rb_tree_delete(%p, %p)\n", T, z);
#endif
    if (z->left != rb_nil)
	rb_tree_delete(T, z->left);
    if (z->right != rb_nil)
	rb_tree_delete(T, z->right);
    if (T->free && z->payload)
	T->free(z->payload);
    rb_free(z);
}

void RB_tree_delete(rb_tree_t * T)
{
#ifdef DEBUG_RB
    fprintf(stderr, "RB_tree_delete(%p)\n", T);
#endif
    if (T) {
	if (T->root != rb_nil)
	    rb_tree_delete(T, T->root);
	free(T);
	if (!--rb_tree_count) {
	    rb_nil = NULL;
	    while (rb_nodes) {
		struct rb_nodearray *a = rb_nodes->next;
		free(rb_nodes);
		rb_nodes = a;
	    }
	}
    }
}

int RB_empty(rb_tree_t * T)
{
    return T == NULL || T->count == 0;
}

int RB_count(rb_tree_t * T)
{
    return T ? T->count : 0;
}

void RB_search_and_delete(rb_tree_t * t, void *q)
{
    rb_node_t *rbn;
    if ((rbn = RB_search(t, q)))
	RB_delete(t, rbn);
}

void *RB_lookup(rb_tree_t * t, void *q)
{
    rb_node_t *rbn = RB_search(t, q);
    if (rbn)
	return rbn->payload;
    return NULL;
}

void *RB_payload_get(rb_node_t * rbn)
{
    return rbn->payload;
}

void RB_payload_unlink(rb_node_t * rbn)
{
    rbn->payload = NULL;
}
