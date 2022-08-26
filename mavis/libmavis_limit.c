/*
 * libmavis_limit.c
 *
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#define MAVIS_name "limit"

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <sys/types.h>
#include <dlfcn.h>

#include "misc/sysconf.h"

#include "log.h"
#include "debug.h"
#include "misc/memops.h"
#include "misc/net.h"
#include "misc/rb.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

#define MAVIS_CTX_PRIVATE		\
	int initialized;		\
	time_t lastpurge;		\
	time_t ip_timeout;		\
	u_int ip_blacklist_count;	\
	time_t ip_blacklist_time;	\
	time_t purge_outdated;		\
	struct cache *cache_blacklist;

#include "mavis.h"

struct item {
    time_t expire;
    u_int count;
    struct in6_addr addr;
    char user[1];
};

struct cache {
    time_t maxage;
    rb_tree_t *items;
};

static void free_payload(void *payload)
{
    free(payload);
}

static struct cache *cache_new(int (*compar)(const void *, const void *), void(*freenode)(void *), time_t maxage)
{
    struct cache *cache;

    cache = Xcalloc(1, sizeof(struct cache));
    cache->items = RB_tree_new(compar, freenode);
    cache->maxage = maxage;
    return cache;
}

static void cache_add_addr(struct cache *cache, char *user, char *addr)
{
    struct item item, *newitem = NULL;
    rb_node_t *t;

    if (!user)
	return;

    if (v6_ptoh(&item.addr, NULL, addr))
	return;

    t = RB_search(cache->items, &item);

    if (!t || strcmp(RB_payload(t, struct item *)->user, user)) {
	if (t)
	    RB_delete(cache->items, t);
	newitem = Xcalloc(1, sizeof(struct item) + strlen(user));
	strcpy(newitem->user, user);
	newitem->count = 1;
	newitem->addr = item.addr;
	newitem->expire = io_now.tv_sec + cache->maxage;
	RB_insert(cache->items, newitem);
    } else {
	struct item *ti = RB_payload(t, struct item *);
	if (io_now.tv_sec > ti->expire)
	    ti->count = 0;
	ti->expire = io_now.tv_sec + cache->maxage;
	ti->count++;
    }
}

static struct item *cache_find_addr(struct cache *cache, char *addr)
{
    struct item item;
    rb_node_t *t = NULL;

    DebugIn(DEBUG_PROC);

    if (!v6_ptoh(&item.addr, NULL, addr))
	t = RB_search(cache->items, &item);
    DebugOut(DEBUG_PROC);
    return t ? RB_payload(t, struct item *) : NULL;
}

static void garbage_collection_one(struct cache *cache)
{
    rb_node_t *t, *u;

    if (cache && cache->items)
	for (t = RB_first(cache->items); t; t = u)
	    if (u = RB_next(t), RB_payload(t, struct item *)->expire < io_now.tv_sec)
		 RB_delete(cache->items, t);
}

static void garbage_collection(mavis_ctx * mcx)
{
    DebugIn(DEBUG_PROC);

    garbage_collection_one(mcx->cache_blacklist);

    DebugOut(DEBUG_PROC);
}

#define HAVE_mavis_drop_in
static void mavis_drop_in(mavis_ctx * mcx)
{
    RB_tree_delete(mcx->cache_blacklist->items);
    Xfree(&mcx->cache_blacklist);
}

/*
purge period =...blacklist time =...blacklist count =...
*/
#define HAVE_mavis_parse_in
static int mavis_parse_in(mavis_ctx * mcx, struct sym *sym)
{
    while (1) {
	switch (sym->code) {
	case S_script:
	    mavis_script_parse(mcx, sym);
	    continue;
	case S_purge:
	    sym_get(sym);
	    parse(sym, S_period);
	    parse(sym, S_equal);
	    mcx->purge_outdated = (time_t) parse_int(sym);
	    continue;
	case S_blacklist:
	    sym_get(sym);
	    switch (sym->code) {
	    case S_time:
		sym_get(sym);
		parse(sym, S_equal);
		mcx->ip_blacklist_time = (time_t) parse_int(sym);;
		break;
	    case S_count:
		sym_get(sym);
		parse(sym, S_equal);
		mcx->ip_blacklist_count = (u_int) parse_int(sym);;
		break;
	    default:
		parse_error_expect(sym, S_time, S_count, S_unknown);
	    }
	    continue;
	case S_eof:
	case S_closebra:
	    return MAVIS_CONF_OK;
	default:
	    parse_error_expect(sym, S_script, S_purge, S_expire, S_closebra, S_unknown);
	}
    }
}


static int compare_addr(const void *a, const void *b)
{
    return v6_cmp(&((struct item *) a)->addr, &((struct item *) b)->addr);
}

#define HAVE_mavis_init_in
static int mavis_init_in(mavis_ctx * mcx)
{
    if (!mcx->initialized) {
	mcx->initialized++;
	mcx->cache_blacklist = cache_new(compare_addr, free_payload, mcx->ip_blacklist_time);
	mcx->lastpurge = io_now.tv_sec;
    }
    return MAVIS_INIT_OK;
}

#define HAVE_mavis_send_in
static int mavis_send_in(mavis_ctx * mcx, av_ctx ** ac)
{
    char *t, *addr;
    t = av_get(*ac, AV_A_TYPE);
    if (!t)
	return MAVIS_FINAL;
    if (io_now.tv_sec > mcx->lastpurge + mcx->purge_outdated) {
	garbage_collection(mcx);
	mcx->lastpurge = io_now.tv_sec;
    }

    addr = av_get(*ac, AV_A_IPADDR);
    if (addr) {
	struct item *item;
	item = cache_find_addr(mcx->cache_blacklist, addr);
	if (mcx->ip_blacklist_count && item && item->count >= mcx->ip_blacklist_count && item->expire > io_now.tv_sec) {
	    av_set(*ac, AV_A_RESULT, AV_V_RESULT_FAIL);
	    av_setf(*ac, AV_A_COMMENT, "client ip blacklisted for "TIME_T_PRINTF " seconds", item->expire - io_now.tv_sec);
	    return MAVIS_FINAL;
	}

    }

    return MAVIS_DOWN;
}

#define HAVE_mavis_recv_out
static int mavis_recv_out(mavis_ctx * mcx, av_ctx ** ac)
{
    char *t = av_get(*ac, AV_A_TYPE);
    char *u = av_get(*ac, AV_A_USER);
    char *i = av_get(*ac, AV_A_IPADDR);
    char *r = av_get(*ac, AV_A_RESULT);
    if (!r)
	r = AV_V_RESULT_FAIL;
    if (t && i && u) {
	if (!strcmp(r, AV_V_RESULT_FAIL)
	    && (!strcmp(t, AV_V_TYPE_TACPLUS)
		|| !strcmp(t, AV_V_TYPE_FTP)
		|| !strcmp(t, AV_V_TYPE_WWW)
		|| !strcmp(t, AV_V_TYPE_POP3)))
	    cache_add_addr(mcx->cache_blacklist, "", i);
    }

    return MAVIS_FINAL;
}

#define HAVE_mavis_new
static void mavis_new(mavis_ctx * mcx)
{
    mcx->ip_blacklist_time = 300;
    mcx->purge_outdated = 300;
}

#include "mavis_glue.c"
