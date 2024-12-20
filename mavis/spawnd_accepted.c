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
#include "misc/mymd5.h"
#include <netinet/tcp.h>
#include <sys/uio.h>
#include <sysexits.h>

static const char rcsid[] __attribute__((used)) = "$Id$";

struct track {
#define MD5_DIGEST_SIZE 16
    u_char digest[MD5_DIGEST_SIZE];
    int i;
    time_t expires;
    struct track *lru_prev;
    struct track *lru_next;
};

static rb_tree_t *trackdb = NULL;

static struct track *track_lru_first = NULL;
static struct track *track_lru_last = NULL;

static void track_lru_remove(struct track *track)
{
    if (track->lru_prev)
	track->lru_prev->lru_next = track->lru_next;

    if (track->lru_next)
	track->lru_next->lru_prev = track->lru_prev;

    if (track == track_lru_first)
	track_lru_first = track->lru_next;

    if (track == track_lru_last)
	track_lru_last = track->lru_prev;

    track->lru_prev = track->lru_next = NULL;
}

static void track_lru_append(struct track *track)
{
    if (track == track_lru_first || track->lru_prev)
	track_lru_remove(track);
    track->lru_prev = track_lru_last;
    if (track_lru_last)
	track_lru_last->lru_next = track;
    if (!track_lru_first)
	track_lru_first = track;
    track_lru_last = track;
    track->lru_next = NULL;
    track->expires = io_now.tv_sec + spawnd_data.tracking_period;
}

static int compare_track(const void *a, const void *b)
{
    return memcmp(&((struct track *) a)->digest, &((struct track *) b)->digest, MD5_DIGEST_SIZE);
}

static void free_track(void *p)
{
    struct track *track = (struct track *) p;
    track->expires = 0;
    track_lru_remove(track);
}

static struct track *alloc_track(void)
{
    if (spawnd_data.tracking_size && (!track_lru_first || track_lru_first->expires > io_now.tv_sec)) {
	int n = spawnd_data.tracking_size;
#define ARRSIZE 1024
	if (n > ARRSIZE)
	    n = ARRSIZE;
#undef ARRSIZE
	spawnd_data.tracking_size -= n;
	struct track *tracks = calloc(n, sizeof(struct track));
	for (int i = 1; i < n; i++) {
	    tracks[i].lru_prev = &tracks[i - 1];
	    tracks[i - 1].lru_next = &tracks[i];
	}
	tracks[n - 1].lru_next = track_lru_first;
	if (track_lru_first)
	    track_lru_first->lru_prev = &tracks[n - 1];
	if (!track_lru_last)
	    track_lru_last = &tracks[n - 1];
	track_lru_first = tracks;
    }
    struct track *track = track_lru_first;
    while (track && track->expires && track->expires < io_now.tv_sec) {
	RB_search_and_delete(trackdb, track);
	track = track->lru_next;
    }

    track = track_lru_first;
    if (track->expires)		// no more entries left, drop least recently used
	RB_search_and_delete(trackdb, track);
    track_lru_append(track);
    return track;
}

static int tracking_lookup(u_char *digest)
{
    if (trackdb) {
	struct track t, *tp;
	memcpy(&t.digest, digest, MD5_DIGEST_SIZE);
	if ((tp = RB_lookup(trackdb, &t))) {
	    track_lru_append(tp);
	    return tp->i;
	}
    }
    return -1;
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

static void tracking_register(u_char *digest, int i)
{
    struct track t, *tp;
    if (spawnd_data.tracking_period < 1)
	return;
    if (!trackdb)
	trackdb = RB_tree_new(compare_track, free_track);
    memcpy(&t.digest, digest, MD5_DIGEST_SIZE);
    tp = RB_lookup(trackdb, &t);
    if (!tp) {
	tp = alloc_track();
	if (!tp)
	    return;
	memcpy(tp->digest, digest, MD5_DIGEST_SIZE);
	RB_insert(trackdb, tp);
    }
    tp->i = i;
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
	struct iovec iov[5];
	size_t iov_len = 0;
	// cover source address
	switch (sa.sa.sa_family) {
#ifdef AF_INET
	    iov[iov_len].iov_base = &sa.sin.sin_addr;
	    iov[iov_len++].iov_len = 4;
	    break;
#endif
#ifdef AF_INET6
	case AF_INET6:
	    iov[iov_len].iov_base = &sa.sin6.sin6_addr;
	    iov[iov_len++].iov_len = 16;
	    break;
#endif
	default:
	    ;
	}
	// cover destination port
	iov[iov_len].iov_base = &ctx->port;
	iov[iov_len++].iov_len = sizeof(ctx->port);
	if (sd) {
	    // TCP: cover protocol
	    u_char u = IPPROTO_TCP;
	    iov[iov_len].iov_base = &u;
	    iov[iov_len++].iov_len = 1;
	} else {
	    // UDP: cover protocol, radius identifier and source port
	    u_char u = IPPROTO_UDP;
	    iov[iov_len].iov_base = &u;
	    iov[iov_len++].iov_len = 1;
	    if (sd_udp->data_len > 21) {
		iov[iov_len].iov_base = &sd_udp->data[21];	// radius identifier
		iov[iov_len++].iov_len = 1;
	    }
	    switch (sa.sa.sa_family) {
#ifdef AF_INET
		iov[iov_len].iov_base = &sa.sin.sin_port;
		iov[iov_len++].iov_len = sizeof(sa.sin.sin_port);
		break;
#endif
#ifdef AF_INET6
	    case AF_INET6:
		iov[iov_len].iov_base = &sa.sin6.sin6_port;
		iov[iov_len++].iov_len = sizeof(sa.sin6.sin6_port);;
		break;
#endif
	    default:
		;
	    }
	}

	u_char digest[MD5_DIGEST_SIZE];
	md5v(digest, sizeof(digest), iov, iov_len);

	do {
	    min = common_data.users_max;
	    min_i = tracking_lookup(digest);
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
		tracking_register(digest, min_i);
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
