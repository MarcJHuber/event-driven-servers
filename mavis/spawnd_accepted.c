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
#include <netinet/in.h>
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

static void track_lru_remove(struct track_data *data, struct track *track)
{
    if (track->lru_prev)
	track->lru_prev->lru_next = track->lru_next;

    if (track->lru_next)
	track->lru_next->lru_prev = track->lru_prev;

    if (track == data->lru_first)
	data->lru_first = track->lru_next;

    if (track == data->lru_last)
	data->lru_last = track->lru_prev;

    track->lru_next = data->lru_first;
    data->lru_first = track;
}

static void track_lru_append(struct track_data *data, struct track *track)
{
    if (track == data->lru_first || track->lru_prev)
	track_lru_remove(data, track);
    track->lru_prev = data->lru_last;
    if (data->lru_last)
	data->lru_last->lru_next = track;
    if (!data->lru_first)
	data->lru_first = track;
    data->lru_last = track;
    track->lru_next = NULL;
    track->expires = io_now.tv_sec + data->tracking_period;
}

static int compare_track(const void *a, const void *b)
{
    return memcmp(&((struct track *) a)->digest, &((struct track *) b)->digest, MD5_DIGEST_SIZE);
}

static struct track *alloc_track(struct track_data *data)
{
    if (data->tracking_size && (!data->lru_first || data->lru_first->expires > io_now.tv_sec)) {
	int n = data->tracking_size;
#define ARRSIZE 1024
	if (n > ARRSIZE)
	    n = ARRSIZE;
#undef ARRSIZE
	data->tracking_size -= n;
	struct track *tracks = calloc(n, sizeof(struct track));
	for (int i = 1; i < n; i++) {
	    tracks[i].lru_prev = &tracks[i - 1];
	    tracks[i - 1].lru_next = &tracks[i];
	}
	tracks[n - 1].lru_next = data->lru_first;
	if (data->lru_first)
	    data->lru_first->lru_prev = &tracks[n - 1];
	if (!data->lru_last)
	    data->lru_last = &tracks[n - 1];
	data->lru_first = tracks;
    }
    struct track *track = data->lru_first;
    while (track && track->expires && track->expires < io_now.tv_sec) {
	track->expires = 0;
	track_lru_remove(data, track);
	RB_search_and_delete(data->db, track);
	track = track->lru_next;
    }

    track = data->lru_first;
    if (track && track->expires) {	// no more entries left, drop least recently used
	track->expires = 0;
	track_lru_remove(data, track);
	RB_search_and_delete(data->db, track);
    }
    if (track)
	track_lru_append(data, track);
    return track;
}

static int tracking_lookup(struct track_data *data, u_char *digest)
{
    if (data->db) {
	struct track t, *tp;
	memcpy(&t.digest, digest, MD5_DIGEST_SIZE);
	if ((tp = RB_lookup(data->db, &t))) {
	    track_lru_append(data, tp);
	    return tp->i;
	}
    }
    return -1;
}

static void spawnd_adjust_tracking_one(struct track_data *data, int old, int new)
{
    if (data->db) {
	rb_node_t *r;
	r = RB_first(data->db);
	while (r) {
	    rb_node_t *rn = RB_next(r);
	    struct track *t = RB_payload(r, struct track *);
	    if (new < 0) {
		t->expires = 0;
		track_lru_remove(data, t);
		RB_delete(data->db, r);
	    } else {
		if (t->i == old)
		    t->i = new;
	    }
	    r = rn;
	}
    }
}

void spawnd_adjust_tracking(int old, int new)
{
    for (int i = 0; i < spawnd_data.listeners_max; i++)
	if (spawnd_data.listener_arr[i]->track_data.db)
	    spawnd_adjust_tracking_one(&spawnd_data.listener_arr[i]->track_data, old, new);

    if (spawnd_data.track_data.db)
	spawnd_adjust_tracking_one(&spawnd_data.track_data, old, new);
}

static void tracking_register(struct track_data *data, u_char *digest, int i)
{
    if (data->tracking_period < 1)
	return;
    if (!data->db)
	data->db = RB_tree_new(compare_track, NULL);
    struct track t, *tp;
    memcpy(&t.digest, digest, MD5_DIGEST_SIZE);
    tp = RB_lookup(data->db, &t);
    if (!tp) {
	tp = alloc_track(data);
	if (!tp)
	    return;
	memcpy(tp->digest, digest, MD5_DIGEST_SIZE);
	RB_insert(data->db, tp);
    }
    tp->i = i;
}

void spawnd_accepted(struct spawnd_context *ctx, int cur)
{
    int s = -1, i, min, min_i, res, flags;
    int one = 1;
    sockaddr_union sa = { 0 };
    socklen_t sa_len = (socklen_t) sizeof(sa);
    int iteration_cur = 0;
    struct in6_addr addr;
    struct scm_data_accept *sd = NULL;
    struct scm_data_udp *sd_udp = NULL;

    DebugIn(DEBUG_NET);

    if (ctx->socktype == SOCK_DGRAM) {

	char buf[4096];
	char cbuf[512];

	struct iovec iov = {
	    .iov_base = buf,
	    .iov_len = sizeof(buf)
	};

	struct msghdr msg = {
	    .msg_name = &sa,
	    .msg_namelen = sizeof(sa),
	    .msg_iov = &iov,
	    .msg_iovlen = 1,
	    .msg_flags = 0,
	    .msg_control = (caddr_t) cbuf,
	    .msg_controllen = sizeof(cbuf)
	};

	ssize_t len = recvmsg(cur, &msg, 0);
	if (len < 1) {
	    DebugOut(DEBUG_NET);
	    return;
	}

	sockaddr_union local_su = {.sa.sa_family = sa.sa.sa_family };

	for (struct cmsghdr * cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
#ifdef IP_PKTINFO
#ifndef SOL_IP
#define SOL_IP IPPROTO_IP
#endif
	    if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_PKTINFO) {
		memcpy(&local_su.sin.sin_addr, &((struct in_pktinfo *) CMSG_DATA(cmsg))->ipi_addr, 4);
		local_su.sa.sa_family = AF_INET;
		break;
	    }
#endif
#ifdef IPV6_PKTINFO
#ifndef SOL_IPV6
#define SOL_IPV6 IPPROTO_IPV6
#endif
	    if (cmsg->cmsg_level == SOL_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
		memcpy(&local_su.sin6.sin6_addr, &((struct in6_pktinfo *) CMSG_DATA(cmsg))->ipi6_addr, 16);
		local_su.sa.sa_family = AF_INET6;
		break;
	    }
#endif
	}
	su_convert(&local_su, sa.sa.sa_family);

	sd_udp = alloca(sizeof(struct scm_data_udp) + len);
	sd_udp->data_len = len;
	memcpy(sd_udp->data, buf, len);
	sd_udp->type = SCM_UDPDATA;
	sd_udp->flags = ctx->sd_flags;
	sd_udp->tls_versions = ctx->dtls_versions;
	sd_udp->aaa_protocol = ctx->aaa_protocol;
	memcpy(sd_udp->realm, ctx->tag, SCM_REALM_SIZE);
	s = socket(sa.sa.sa_family, SOCK_DGRAM, 0);
	int one = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *) &one, (socklen_t) sizeof(one));

	switch (sa.sa.sa_family) {
#ifdef AF_INET
	case AF_INET:
	    local_su.sin.sin_port = htons(ctx->port);
	    break;
#endif
#ifdef AF_INET6
	case AF_INET6:
	    local_su.sin6.sin6_port = htons(ctx->port);
	    break;
#endif
	default:
	    DebugOut(DEBUG_NET);
	    return;
	}
	if (-1 < su_bind(s, &local_su))
	    su_connect(s, &sa);
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
	sd->type = SCM_ACCEPT;
	sd->flags = ctx->sd_flags;
	sd->tls_versions = ctx->tls_versions;
	sd->aaa_protocol = ctx->aaa_protocol;
	sd->protocol = ctx->protocol;
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
	struct track_data *track_data = (ctx->track_data.tracking_period > 0) ? &ctx->track_data : &spawnd_data.track_data;
	struct iovec iov[5];
	size_t iov_len = 0;
	// cover source address
	switch (sa.sa.sa_family) {
#ifdef AF_INET
	case AF_INET:
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
	    // UDP: cover protocol and source port
	    u_char u = IPPROTO_UDP;
	    iov[iov_len].iov_base = &u;
	    iov[iov_len++].iov_len = 1;
	    switch (sa.sa.sa_family) {
#ifdef AF_INET
	    case AF_INET:
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

	min_i = tracking_lookup(&ctx->track_data, digest);
	do {
	    min = common_data.users_max;
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
	    } else if (track_data->tracking_period > 0)
		tracking_register(track_data, digest, min_i);
	}
	while (res);

	if (s > -1)
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
