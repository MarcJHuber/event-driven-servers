/*
 * libmavis_cache.c
 *
 * (C)1999-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * general av-pair caching
 *
 * $Id$
 *
 */

#define MAVIS_name "cache"

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <sysexits.h>
#include <dlfcn.h>

#include "log.h"
#include "debug.h"
#include "misc/memops.h"
#include "misc/rb.h"
#include "misc/crc32.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

#define AVPC_TABLE_SIZE 1

struct cache {
    char *type;
    time_t maxage;
    fd_set cmp_set;
    fd_set add_set;
    u_int count;
    unsigned long long counter_query;
    unsigned long long counter_cached;
    unsigned long long counter_p_query;
    unsigned long long counter_p_cached;
    rb_tree_t *items;
};

#define MAVIS_CTX_PRIVATE			\
	int initialized;			\
	time_t purge_outdated;			\
	struct cache cache[AVPC_TABLE_SIZE];	\
	time_t lastdump;			\
	time_t lastpurge;			\
	time_t startup_time;			\
	int cache_lookup_succeeded;

#include "mavis.h"

struct item {
    time_t expire;
    u_int crc32;
    char *add;
    char cmp[1];
};

static void free_item(void *payload)
{
    free(payload);
}

static int cmp_item(const void *a, const void *b)
{
    if (((struct item *) a)->crc32 < ((struct item *) b)->crc32)
	return -1;
    if (((struct item *) a)->crc32 > ((struct item *) b)->crc32)
	return +1;
    return strcmp(((struct item *) a)->cmp, ((struct item *) b)->cmp);
}

static int find_entry(av_ctx * ac, struct cache *cache)
{
    rb_node_t *result;
    struct item *i = (struct item *) alloca(sizeof(struct item) + BUFSIZE_MAVIS);

    Debug((DEBUG_PROC, "+ %s: %.8lx\n", __func__, (u_long) cache));

    if ((av_array_to_char(ac, i->cmp, BUFSIZE_MAVIS, &cache->cmp_set) > 0)
	&& ((i->crc32 = crc32_update(INITCRC32, (u_char *) i->cmp, strlen(i->cmp))), (result = RB_search(cache->items, i)))) {
	Debug((DEBUG_PROC, " found\n"));
	if (io_now.tv_sec < (i = RB_payload(result, struct item *))->expire) {
	    av_char_to_array(ac, i->add, &cache->add_set);
	    Debug((DEBUG_PROC, "- %s (expired)\n", __func__));
	    return -1;
	}
	RB_delete(cache->items, result);
	cache->count--;
    }

    Debug((DEBUG_PROC, "- %s (not found)\n", __func__));
    return 0;
}

static void garbage_collection(mavis_ctx * mcx)
{
    rb_node_t *t, *u;

    DebugIn(DEBUG_PROC);

    for (int i = 0; i < AVPC_TABLE_SIZE; i++)
	for (t = RB_first(mcx->cache[i].items); t; t = u)
	    if (u = RB_next(t), RB_payload(t, struct item *)->expire < io_now.tv_sec) {
		RB_delete(mcx->cache[i].items, t);
		mcx->cache[i].count--;
	    }

    DebugOut(DEBUG_PROC);
}

static int cache_lookup(mavis_ctx * mcx, av_ctx * ac)
{
    char *s = av_get(ac, AV_A_TYPE);

    if (!strcasecmp(s, AV_V_TYPE_LOGSTATS)) {
	for (int i = 0; i < AVPC_TABLE_SIZE; i++) {
	    if (mcx->cache[i].counter_query)
		logmsg("STAT %s: %s: Q=%llu C=%llu T=%lld"
		       " q=%llu c=%llu t=%lld #=%u",
		       MAVIS_name,
		       mcx->cache[i].type,
		       mcx->cache[i].counter_query,
		       mcx->cache[i].counter_cached,
		       (long long) (io_now.tv_sec - mcx->startup_time),
		       mcx->cache[i].counter_p_query, mcx->cache[i].counter_p_cached, (long long) (io_now.tv_sec - mcx->lastdump), mcx->cache[i].count);
	    mcx->cache[i].counter_p_query = mcx->cache[i].counter_p_cached = 0;
	}

	mcx->lastdump = io_now.tv_sec;
	return 0;
    }

    for (int i = 0; i < AVPC_TABLE_SIZE; i++)
	if (!strcasecmp(mcx->cache[i].type, s)) {
	    mcx->cache[i].counter_query++, mcx->cache[i].counter_p_query++;
	    if (mcx->cache[i].items && find_entry(ac, &mcx->cache[i])) {
		mcx->cache[i].counter_cached++, mcx->cache[i].counter_p_cached++;
		return -1;
	    }
	    return 0;
	}
    return 0;
}

static void cache_set(mavis_ctx * mcx, av_ctx * ac)
{
    Debug((DEBUG_PROC, " cache_set\n"));

    char *s = av_get(ac, AV_A_TYPE);

    for (int i = 0; i < AVPC_TABLE_SIZE; i++)
	if (!strcasecmp(mcx->cache[i].type, s)) {
	    Debug((DEBUG_PROC, "  cache @ %.8lx\n", (u_long) mcx->cache + i));
	    if (mcx->cache[i].items && 0 < mcx->cache[i].maxage) {
		struct item *item;
		char buffer[BUFSIZE_MAVIS];
		int length1, length2;
		rb_node_t *rbn;

		length1 = av_array_to_char(ac, buffer, sizeof(buffer), &mcx->cache[i].cmp_set);

		length2 = av_array_to_char(ac, buffer + length1 + 1, sizeof(buffer) - length1 - 1, &mcx->cache[i].add_set);

		if (length1 < 0 || length2 < 0)
		    return;

		item = Xcalloc(1, sizeof(struct item) + length1 + length2 + 1);

		item->expire = io_now.tv_sec + mcx->cache[i].maxage;
		item->add = item->cmp + length1 + 1;
		memcpy(item->cmp, buffer, length1 + length2 + 2);
		item->crc32 = crc32_update(INITCRC32, (u_char *) item->cmp, length1);

		rbn = RB_search(mcx->cache[i].items, item);
		if (rbn) {
		    Debug((DEBUG_PROC, " already cached\n"));
		    free(item);
		} else {
		    Debug((DEBUG_PROC, " inserted\n"));
		    RB_insert(mcx->cache[i].items, item);
		    mcx->cache[i].count++;
		}
	    }
	    return;
	}
}

#define HAVE_mavis_init_in
static int mavis_init_in(mavis_ctx * mcx)
{
    int i = 0;
    if (mcx->initialized)
	return MAVIS_INIT_OK;

#define A(x) FD_SET (x, &mcx->cache[i].add_set)
#define C(x) FD_SET (x, &mcx->cache[i].cmp_set)

    mcx->cache[i].type = AV_V_TYPE_FTP;
    C(AV_A_USER);
    C(AV_A_VHOST);
    C(AV_A_CERTSUBJ);
    A(AV_A_UID);
    A(AV_A_GID);
    A(AV_A_HOME);
    A(AV_A_ROOT);
    A(AV_A_QUOTA_LIMIT);
    A(AV_A_QUOTA_PATH);
    A(AV_A_FTP_ANONYMOUS);
    A(AV_A_ANON_INCOMING);
    A(AV_A_GIDS);
    A(AV_A_EMAIL);
    A(AV_A_UMASK);
    A(AV_A_TRAFFICSHAPING);
    A(AV_A_CLASS);
    A(AV_A_DBPASSWORD);
    A(AV_A_DBCERTSUBJ);
    A(AV_A_SHELL);
    i++;

#undef A
#undef C

    if (AVPC_TABLE_SIZE != i) {
	logmsg("%s: Bug (%s:%d)", MAVIS_name, __FILE__, __LINE__);
	exit(EX_SOFTWARE);
    }

    return MAVIS_INIT_OK;
}

#define HAVE_mavis_drop_in
static void mavis_drop_in(mavis_ctx * mcx)
{
    for (int k = 0; k < AVPC_TABLE_SIZE; k++)
	RB_tree_delete(mcx->cache[k].items);
}

#define HAVE_mavis_parse_in
static int mavis_parse_in(mavis_ctx * mcx, struct sym *sym)
{
    if (!mcx->initialized) {
	mcx->lastdump = mcx->lastpurge = mcx->startup_time = io_now.tv_sec;
	for (int i = 0; i < AVPC_TABLE_SIZE; i++)
	    mcx->cache[i].items = RB_tree_new(cmp_item, free_item);
	mavis_init_in(mcx);
	mcx->initialized = 1;
    }

    while (1) {
	switch (sym->code) {
	case S_script:
	    mavis_script_parse(mcx, NULL, sym);
	    continue;
	case S_purge:
	    sym_get(sym);
	    parse(sym, S_period);
	    parse(sym, S_equal);
	    mcx->purge_outdated = (long unsigned) parse_int(sym);
	    continue;
	case S_expire:
	    sym_get(sym);
	    if (sym->code == S_equal) {
		int i, j;
		sym_get(sym);
		j = parse_int(sym);
		for (i = 0; i < AVPC_TABLE_SIZE; i++)
		    mcx->cache[i].maxage = (long unsigned) j;
	    } else {
		for (int i = 0; i < AVPC_TABLE_SIZE; i++) {
		    if (!strcasecmp(mcx->cache[i].type, sym->buf)) {
			sym_get(sym);
			parse(sym, S_equal);
			mcx->cache[i].maxage = (long unsigned) parse_int(sym);
			continue;
		    }
		}
	    }

	    continue;
	case S_eof:
	case S_closebra:
	    return MAVIS_CONF_OK;
	case S_action:
	    mavis_module_parse_action(mcx, sym);
	    continue;
	default:
	    parse_error_expect(sym, S_script, S_purge, S_expire, S_action, S_closebra, S_unknown);
	}
    }
}


#define HAVE_mavis_send_in
static int mavis_send_in(mavis_ctx * mcx, av_ctx ** ac)
{
    if (io_now.tv_sec > mcx->lastpurge + mcx->purge_outdated) {
	garbage_collection(mcx);
	mcx->lastpurge = io_now.tv_sec;
    }

    if ((mcx->cache_lookup_succeeded = cache_lookup(mcx, *ac))) {
	av_set(*ac, AV_A_COMMENT, "cached");
	return MAVIS_FINAL;
    }

    return MAVIS_DOWN;
}

#define HAVE_mavis_recv_in
static int mavis_recv_in(mavis_ctx * mcx, av_ctx ** ac __attribute__((unused)), char *serial __attribute__((unused)))
{
    mcx->cache_lookup_succeeded = 0;
    return MAVIS_DOWN;
}

#define HAVE_mavis_recv_out
static int mavis_recv_out(mavis_ctx * mcx, av_ctx ** ac)
{
    char *r = av_get(*ac, AV_A_RESULT);
    char *d = av_get(*ac, AV_A_DBPASSWORD);
    char *o = av_get(*ac, AV_A_PASSWORD_ONESHOT);
    if (!o && (d || (r && !strcmp(r, AV_V_RESULT_OK)))
	&& !mcx->cache_lookup_succeeded)
	cache_set(mcx, *ac);
    mcx->cache_lookup_succeeded = 0;
    return MAVIS_FINAL;
}

#define HAVE_mavis_new
static void mavis_new(mavis_ctx * mcx)
{
    mcx->purge_outdated = 300;
}

#include "mavis_glue.c"
