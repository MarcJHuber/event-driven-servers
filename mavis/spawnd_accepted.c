/*
 * accepted.c
 *
 * (C)1999-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "spawnd_headers.h"
#include <netinet/tcp.h>
#include <sysexits.h>

static const char rcsid[] __attribute__((used)) = "$Id$";

struct track {
    struct in6_addr addr;
    int i;
    time_t expires;
    struct track *nextfree;
};

static rb_tree_t *trackdb = NULL;
static struct track *tracks = NULL;

static int compare_track(const void *a, const void *b)
{
    return memcmp(&((struct track *) a)->addr, &((struct track *) b)->addr, sizeof(struct in6_addr));
}

static void free_track(void *p)
{
    ((struct track *) p)->nextfree = tracks;
    tracks = p;
}

static struct track *alloc_track(void)
{
    struct track *t;
    if (!tracks && (spawnd_data.tracking_size > 0)) {
	int left = spawnd_data.tracking_size;
	if (left > 1024)
	    left = 1024;
	tracks = calloc(left, sizeof(struct track));
	spawnd_data.tracking_size -= left;
	left--;
	for (int i = 0; i < left; i++)
	    tracks[i].nextfree = &tracks[i + 1];
    }
    t = tracks;
    if (tracks)
	tracks = tracks->nextfree;
    return t;
}

static int tracking_lookup(struct in6_addr *addr)
{
    if (trackdb) {
	struct track t, *tp;
	t.addr = *addr;
	if ((tp = RB_lookup(trackdb, &t)))
	    return tp->i;
    }
    return -1;
}

void spawnd_cleanup_tracking(void)
{
    if (trackdb) {
	rb_node_t *r;
	r = RB_first(trackdb);
	while (r) {
	    rb_node_t *rn = RB_next(r);
	    if (RB_payload(r, struct track *)->expires < io_now.tv_sec)
		 RB_delete(trackdb, r);
	    r = rn;
	}
    }
}

void spawnd_adjust_tracking(int old, int new)
{
    if (trackdb) {
	rb_node_t *r;
	r = RB_first(trackdb);
	while (r) {
	    rb_node_t *rn = RB_next(r);
	    if (new < 0)
		RB_delete(trackdb, r);
	    else {
		struct track *t = RB_payload(r, struct track *);
		if (t->i == old)
		    t->i = new;
	    }
	    r = rn;
	}
    }
}

static void tracking_register(struct in6_addr *addr, int i)
{
    struct track t, *tp;
    if (spawnd_data.tracking_period < 1)
	return;
    if (!trackdb)
	trackdb = RB_tree_new(compare_track, free_track);
    memcpy(&t.addr, addr, sizeof(struct in6_addr));
    tp = RB_lookup(trackdb, &t);
    if (!tp) {
	tp = alloc_track();
	if (!tp)
	    return;
	tp->addr = *addr;
	RB_insert(trackdb, tp);
    }
    tp->i = i;
    tp->expires = io_now.tv_sec + spawnd_data.tracking_period;
}

void spawnd_accepted(struct spawnd_context *ctx, int cur)
{
    int s = -1, i, min, min_i, res, flags;
    int one = 1;
    sockaddr_union sa;
    socklen_t sa_len = (socklen_t) sizeof(sa);
    int iteration_cur = 0;
    struct in6_addr addr;
    struct scm_data_accept *sd = NULL;
    struct scm_data_udp *sd_udp = NULL;

    DebugIn(DEBUG_NET);

    if (ctx->socktype == SOCK_DGRAM) {
	char buf[4096];
	ssize_t len = recvfrom(cur, &buf, sizeof(buf), 0, &sa.sa, &sa_len);
	if (len < 1) {
	    DebugOut(DEBUG_NET);
	    return;
	}
	sd_udp = alloca(sizeof(struct scm_data_udp) + len);
	sd_udp->data_len = len;
	memcpy(sd_udp->data, buf, len);
	sd_udp->sock = cur;
	sd_udp->type = SCM_UDPDATA;
	sd_udp->rad_acct = ctx->rad_acct;
	memcpy(sd_udp->realm, ctx->tag, SCM_REALM_SIZE);
	sd_udp->protocol = sa.sa.sa_family;
	switch (sa.sa.sa_family) {
#ifdef AF_INET
	case AF_INET:
	    memcpy(&sd_udp->src, &sa.sin.sin_addr, 4);
	    sd_udp->src_port = ntohs(sa.sin.sin_port);
	    break;
#endif
#ifdef AF_INET6
	case AF_INET6:
	    memcpy(&sd_udp->src, &sa.sin6.sin6_addr, 16);
	    sd_udp->src_port = ntohs(sa.sin6.sin6_port);
	    break;
#endif
	default:
	    DebugOut(DEBUG_NET);
	    return;
	}
	sd_udp->dst_port = ctx->port;
    } else {
	s = accept(cur, &sa.sa, &sa_len);
	if (s < 0) {
	    if (errno != EAGAIN)
		logerr("accept (%s:%d)", __FILE__, __LINE__);
	    DebugOut(DEBUG_NET);
	    return;
	}

	if (common_data.users_cur == common_data.users_max_total) {
	    close(s);
	    DebugOut(DEBUG_NET);
	    return;
	}

	if (!spawnd_acl_check(&sa)) {
	    char buf[INET6_ADDRSTRLEN];
	    close(s);
	    if (errno != EAGAIN)
		logerr("connection attempt from [%s] rejected", su_ntop(&sa, buf, (socklen_t) sizeof(buf)));
	    DebugOut(DEBUG_NET);
	    return;
	}

	flags = fcntl(s, F_GETFD, 0) | FD_CLOEXEC;
	fcntl(s, F_SETFD, flags);

	setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char *) &one, (socklen_t) sizeof(one));

#ifdef TCP_KEEPCNT		/* __linux__ */
	if ((ctx->keepcnt > -1)
	    && (setsockopt(s, IPPROTO_TCP, TCP_KEEPCNT, (char *) &ctx->keepcnt, (socklen_t) sizeof(ctx->keepcnt)) < 0))
	    ctx->keepcnt = -1;
#endif
#ifdef TCP_KEEPIDLE		/* __linux__ */
	if ((ctx->keepidle > -1)
	    && (setsockopt(s, IPPROTO_TCP, TCP_KEEPIDLE, (char *) &ctx->keepidle, (socklen_t) sizeof(ctx->keepidle)) < 0))
	    ctx->keepidle = -1;
#endif
#ifdef TCP_KEEPINTVL		/* __linux__ */
	if ((ctx->keepintvl > -1)
	    && (setsockopt(s, IPPROTO_TCP, TCP_KEEPINTVL, (char *) &ctx->keepintvl, (socklen_t) sizeof(ctx->keepintvl)) < 0))
	    ctx->keepintvl = -1;
#endif
#ifdef TCP_KEEPALIVE		/* __APPLE__ */
	if ((ctx->keepidle > -1)
	    && (setsockopt(s, IPPROTO_TCP, TCP_KEEPALIVE, (char *) &ctx->keepidle, (socklen_t) sizeof(ctx->keepidle)) < 0))
	    ctx->keepidle = -1;
#endif

	sd = alloca(sizeof(struct scm_data_accept));
	sd->type = SCM_ACCEPT, sd->haproxy = ctx->haproxy ? 1 : 0, sd->use_tls = ctx->use_ssl ? 1 : 0, sd->protocol = ctx->protocol;
	memcpy(sd->realm, ctx->tag, SCM_REALM_SIZE);
    }

    /* Server selection algorithm */

    if (!common_data.singleprocess)
	while (common_data.servers_cur < common_data.servers_min)
	    spawnd_add_child();
    su_ptoh(&sa, &addr);

    if (common_data.singleprocess)
	common_data.scm_send_msg(-1, sd ? (struct scm_data *) sd : (struct scm_data *) sd_udp, s);
    else {
	do {
	    min = common_data.users_max;
	    min_i = tracking_lookup(&addr);
	    if (min_i > -1 && spawnd_data.server_arr[min_i]->use >= common_data.users_max)
		min_i = -1;

	    if (min_i < 0)
		for (int i = 0; i < common_data.servers_min && i < common_data.servers_cur; i++)
		    if (spawnd_data.server_arr[i]->use < common_data.users_min && spawnd_data.server_arr[i]->use < min)
			min_i = i, min = spawnd_data.server_arr[i]->use;

	    if (min_i < 0)
		for (int i = common_data.servers_min; i < common_data.servers_cur; i++)
		    if (spawnd_data.server_arr[i]->use < common_data.users_min && spawnd_data.server_arr[i]->use < min)
			min_i = i, min = spawnd_data.server_arr[i]->use;

	    if (min_i < 0 && common_data.servers_cur < common_data.servers_max) {
		spawnd_add_child();
		min_i = common_data.servers_cur - 1, min = 0;
	    }

	    if (min_i < 0)
		for (int i = 0; i < common_data.servers_cur; i++)
		    if (spawnd_data.server_arr[i]->use < common_data.users_max && spawnd_data.server_arr[i]->use < min)
			min_i = i, min = spawnd_data.server_arr[i]->use;

	    /* min_i is our selected server. Or -1, which can't happen. */

	    if (min_i == -1) {
		logmsg("BUG (%s:%d)", __FILE__, __LINE__);
		exit(EX_SOFTWARE);
	    }

	    res = common_data.scm_send_msg(spawnd_data.server_arr[min_i]->fn, sd ? (struct scm_data *) sd : (struct scm_data *) sd_udp, s);

	    if (res) {
		logerr("scm_send_msg (%s:%d), pid: %d", __FILE__, __LINE__, (int) spawnd_data.server_arr[min_i]->pid);
		spawnd_cleanup_internal(spawnd_data.server_arr[min_i], spawnd_data.server_arr[min_i]->fn);
		if (iteration_cur++ == common_data.servers_max) {
		    /*
		     * This can't possibly happen. We did start additional server
		     * processes in most of the previous iterations.
		     */
		    logmsg("Giving up. Spawned server processes are probably broken." "(%s:%d)", __FILE__, __LINE__);
		    exit(EX_TEMPFAIL);
		}
	    } else if (spawnd_data.tracking_period > 0)
		tracking_register(&addr, min_i);
	}
	while (res);

	close(s);

	spawnd_data.server_arr[min_i]->use++, common_data.users_cur++;
    }

    if (common_data.users_cur == common_data.users_max_total) {
	logmsg("limit of %d concurrent users reached, %s new connections", common_data.users_cur, spawnd_data.overload_hint);
	set_proctitle(ACCEPT_NO);
	spawnd_data.listeners_inactive = -1;
	for (i = 0; i < spawnd_data.listeners_max; i++)
	    if (spawnd_data.listener_arr[i]->listen_backlog != spawnd_data.listener_arr[i]->overload_backlog)
		listen(spawnd_data.listener_arr[i]->fn, spawnd_data.listener_arr[i]->overload_backlog);
	switch (spawnd_data.overload) {
	case S_queue:
	    for (i = 0; i < spawnd_data.listeners_max; i++)
		io_clr_i(ctx->io, spawnd_data.listener_arr[i]->fn);
	    break;
	case S_reset:
	    for (i = 0; i < spawnd_data.listeners_max; i++) {
		io_close(spawnd_data.listener_arr[i]->io, spawnd_data.listener_arr[i]->fn);
		spawnd_data.listener_arr[i]->fn = -1;
	    }
	    break;
	default:
	    ;
	}

    } else
	set_proctitle(ACCEPT);

    DebugOut(DEBUG_NET);
}
