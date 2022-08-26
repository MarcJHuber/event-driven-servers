/*
 * libmavis_remote.c
 *
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#define MAVIS_name "remote"

#include "misc/sysconf.h"

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <dlfcn.h>

#include "misc/memops.h"
#include "misc/io.h"
#include "debug.h"
#include "misc/crc32.h"
#include "log.h"
#include "misc/rb.h"
#include "misc/net.h"
#include "misc/strops.h"

struct remote_addr_s;

#define MAVIS_CTX_PRIVATE			\
	int sock;				\
	int tries;				\
	int timeout;				\
	int rebalance;				\
	int request_count;			\
	sockaddr_union *local_addr;		\
	struct remote_addr_s *remote_addr;	\
	rb_tree_t *retransmit;			\
	rb_tree_t *retransmit_by_app_ctx;	\
	rb_tree_t *outgoing;			\
	time_t lastdump;			\
	time_t startup_time;

#include "mavis.h"
#include "av_send.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

struct remote_addr_s {
    sockaddr_union sa;
    struct blowfish_ctx *blowfish;
    u_long backlog;
    u_long backlog_max;
    u_long backlog_max_p;
    unsigned long long count_s;
    unsigned long long count_s_p;
    unsigned long long count_r;
    unsigned long long count_r_p;
    struct remote_addr_s *next;
};

struct query {
    mavis_ctx *mcx;
    struct remote_addr_s *ra;
    av_ctx *ac;
    av_ctx *ac_bak;
    int tries;
    int result;
    u_int serial_crc;
};

static int udp_bind(sockaddr_union * sa)
{
    int s;
#ifdef DEBUG
    char buf[INET6_ADDRSTRLEN];
#endif

    Debug((DEBUG_MAVIS, "+ %s (%s:%u)\n", __func__, su_ntop(sa, buf, (int) sizeof(buf)), (unsigned) su_get_port(sa)));

    if ((s = su_socket(sa->sa.sa_family, SOCK_DGRAM, 0)) < 0) {
	Debug((DEBUG_MAVIS, "- %s: socket() failed\n", __func__));
	return -1;
    }
    if (su_bind(s, &(*sa)) < 0) {
	close(s);
	Debug((DEBUG_MAVIS, "- %s: bind() failed\n", __func__));
	return -1;
    }

    DebugOut(DEBUG_MAVIS);
    return s;
}

static struct remote_addr_s *av_recv(mavis_ctx * mcx, av_ctx * ac, int sock, sockaddr_union * sa)
{
    ssize_t buflen;
    socklen_t salen = (socklen_t) sizeof(sockaddr_union);
    struct remote_addr_s *ra = NULL;
    a_char av_buffer[BUFSIZE_MAVIS / sizeof(a_char) + 1];

    DebugIn(DEBUG_MAVIS);

    av_clear(ac);
    av_buffer->s[0] = 0;

    buflen = Recvfrom(sock, av_buffer->s, BUFSIZE_MAVIS - 1, 0, &sa->sa, &salen);

    if (buflen > 0) {
	for (ra = mcx->remote_addr; ra && !su_equal(&ra->sa, sa); ra = ra->next);

	if (ra) {
	    av_buffer->s[buflen] = 0;
	    if (ra->blowfish)
		blowfish_dec(ra->blowfish, av_buffer, buflen);
	    av_char_to_array(ac, av_buffer->s, NULL);
	}
    }
    DebugOut(DEBUG_MAVIS);
    return ra;
}

static int compare_serial(const void *v1, const void *v2)
{
    if (((struct query *) v1)->serial_crc < ((struct query *) v2)->serial_crc)
	return -1;
    if (((struct query *) v1)->serial_crc > ((struct query *) v2)->serial_crc)
	return +1;
    return strcmp(((struct query *) v1)->ac->arr[AV_A_SERIAL], ((struct query *) v2)->ac->arr[AV_A_SERIAL]);
}

static int compare_app_ctx(const void *v1, const void *v2)
{
    if (((struct query *) v1)->ac->app_ctx < ((struct query *) v2)->ac->app_ctx)
	return -1;
    if (((struct query *) v1)->ac->app_ctx > ((struct query *) v2)->ac->app_ctx)
	return +1;
    return 0;
}

static void free_payload(void *p)
{
    av_free(((struct query *) p)->ac);
    av_free(((struct query *) p)->ac_bak);
    free(p);
}

static void udp_error(void *ctx __attribute__((unused)), int cur)
{
    int sockerr;
    socklen_t sockerrlen = (socklen_t) sizeof(sockerr);
    getsockopt(cur, SOL_SOCKET, SO_ERROR, (char *) &sockerr, &sockerrlen);
}

static void mavis_io(mavis_ctx *, int);

#define HAVE_mavis_init_in
static int mavis_init_in(mavis_ctx * mcx)
{
    int result = MAVIS_INIT_OK;
    DebugIn(DEBUG_MAVIS);

    mcx->lastdump = mcx->startup_time = io_now.tv_sec;

    if (!mcx->remote_addr) {
	logmsg("FATAL: no valid remote address specified");
	Debug((DEBUG_MAVIS, "- %s: no valid remote address\n", __func__));
	return MAVIS_INIT_OK;
    }

    if (!mcx->local_addr) {
	mcx->local_addr = Xcalloc(1, sizeof(sockaddr_union));
	mcx->local_addr->sa.sa_family = mcx->remote_addr->sa.sa.sa_family;
    }

    if (mcx->sock > -1)
	close(mcx->sock);

    mcx->sock = udp_bind(mcx->local_addr);

    Debug((DEBUG_PROC, "bound to socket %d\n", mcx->sock));
    if (mcx->io) {
	io_register(mcx->io, mcx->sock, mcx);
	io_set_cb_i(mcx->io, mcx->sock, (void *) mavis_io);
	io_clr_o(mcx->io, mcx->sock);
	io_set_cb_e(mcx->io, mcx->sock, (void *) udp_error);
	io_set_cb_h(mcx->io, mcx->sock, (void *) udp_error);
	io_set_i(mcx->io, mcx->sock);
    }

    mcx->retransmit = RB_tree_new(compare_serial, NULL);
    mcx->retransmit_by_app_ctx = RB_tree_new(compare_app_ctx, NULL);
    mcx->outgoing = RB_tree_new(compare_app_ctx, free_payload);
    Debug((DEBUG_MAVIS, "- %s = %d\n", __func__, mcx->sock));
    return result;
}

struct socket_info {
    struct blowfish_ctx *blowfish;
    mavis_ctx *mcx;
};

static int add_ra(sockaddr_union * su, void *data)
{
    mavis_ctx *mcx = ((struct socket_info *) data)->mcx;
    struct remote_addr_s *ra = Xcalloc(1, sizeof(struct remote_addr_s));
    ra->next = mcx->remote_addr;
    ra->blowfish = ((struct socket_info *) data)->blowfish;
    memcpy(&ra->sa, su, sizeof(sockaddr_union));
    mcx->remote_addr = ra;
    return 0;

}

//local address =...
//  rebalance = <n >
//   dst = { path =...address =...port =...blowfish(key | file) =... }
//timeout =...tries =...
#define HAVE_mavis_parse_in
static int mavis_parse_in(mavis_ctx * mcx, struct sym *sym)
{
    char *ad = NULL, *po = NULL;
    struct socket_info si;
    char blowfish_key[73];
    ssize_t blowfish_key_len = 0;
    int fn;
    while (1) {
	switch (sym->code) {
	case S_script:
	    mavis_script_parse(mcx, sym);
	    continue;
	case S_local:
	    sym_get(sym);
	    parse(sym, S_address);
	    parse(sym, S_equal);
	    if (!mcx->local_addr)
		mcx->local_addr = Xcalloc(1, sizeof(sockaddr_union));
	    if (su_pton(mcx->local_addr, sym->buf))
		parse_error(sym, "Expected a local address, but got '%s'", sym->buf);
	    sym_get(sym);
	    continue;
	case S_rebalance:
	    sym_get(sym);
	    parse(sym, S_equal);
	    mcx->rebalance = parse_int(sym);
	    continue;
	case S_timeout:
	    sym_get(sym);
	    parse(sym, S_equal);
	    mcx->timeout = parse_int(sym);
	    continue;
	case S_tries:
	    sym_get(sym);
	    parse(sym, S_equal);
	    mcx->tries = parse_int(sym);
	    continue;
	case S_server:
	case S_dst:{
		ad = NULL, po = NULL;
		blowfish_key_len = 0;

		sym_get(sym);
		if (sym->code == S_equal)
		    sym_get(sym);
		parse(sym, S_openbra);
		while (sym->code != S_closebra && sym->code != S_eof) {
		    switch (sym->code) {
		    case S_path:
		    case S_address:
			sym_get(sym);
			parse(sym, S_equal);
			strset(&ad, sym->buf);
			sym_get(sym);
			continue;
		    case S_port:
			sym_get(sym);
			parse(sym, S_equal);
			strset(&po, sym->buf);
			sym_get(sym);
			continue;
		    case S_blowfish:
			sym_get(sym);
			switch (sym->code) {
			case S_key:
			    sym_get(sym);
			    parse(sym, S_equal);
			    strncpy(blowfish_key, sym->buf, 72);
			    blowfish_key[72] = 0;
			    blowfish_key_len = strlen(blowfish_key);
			    sym_get(sym);
			    continue;
			case S_keyfile:
			    sym_get(sym);
			    parse(sym, S_equal);
			    fn = open(sym->buf, O_RDONLY);
			    if (fn > -1) {
				blowfish_key_len = Read(fn, blowfish_key, 72);
				close(fn);
				if (blowfish_key_len < 0)
				    blowfish_key_len = 0;
			    } else
				logerr("FATAL: open %s", sym->buf);
			    sym_get(sym);
			    continue;
			default:
			    parse_error_expect(sym, S_key, S_keyfile, S_unknown);
			}
			continue;
		    default:
			parse_error_expect(sym, S_path, S_address, S_port, S_blowfish, S_unknown);
		    }
		}
		if (blowfish_key_len > 0)
		    si.blowfish = blowfish_init(blowfish_key, blowfish_key_len);
		else
		    si.blowfish = NULL;
		si.mcx = mcx;
		if (su_addrinfo(ad ? ad : "0.0.0.0", po ? po : "9001", SOCK_DGRAM, PF_UNSPEC, 0, &si, add_ra))
		    logerr("FATAL: address or port unparsable");
		Xfree(&ad);
		Xfree(&po);
		parse(sym, S_closebra);
		continue;
	case S_eof:
	case S_closebra:
		return MAVIS_CONF_OK;
	default:
		parse_error_expect(sym, S_script, S_userid, S_groupid, S_path, S_mode, S_closebra, S_unknown);
	    }
	}
    }
}

#define HAVE_mavis_drop_in
static void mavis_drop_in(mavis_ctx * mcx)
{
    struct remote_addr_s *ra, *rat;
    rb_node_t *rb, *rbn;
    if (mcx->io)
	io_close(mcx->io, mcx->sock);
    else if (mcx->sock > -1)
	close(mcx->sock);
    for (ra = mcx->remote_addr; ra; ra = rat) {
	rat = ra->next;
	if (ra->blowfish)
	    free(ra->blowfish);
	free(ra);
    }

    mcx->remote_addr = NULL;
    Xfree(&mcx->local_addr);
    RB_tree_delete(mcx->retransmit_by_app_ctx);
    for (rb = RB_first(mcx->retransmit); rb; rb = rbn) {
	struct query *q = RB_payload(rb, struct query *);
	rbn = RB_next(rb);
	io_sched_pop(mcx->io, q);
	free_payload(q);
    }

    RB_tree_delete(mcx->retransmit);
    RB_tree_delete(mcx->outgoing);
}

#define HAVE_mavis_cancel_in
static int mavis_cancel_in(mavis_ctx * mcx, void
			   *app_ctx)
{
    struct query q;
    rb_node_t *r;
    q.ac = av_new(NULL, app_ctx);
    r = RB_search(mcx->retransmit_by_app_ctx, &q);
    if (r) {
	struct query *qp = RB_payload(r, struct query *);
	io_sched_pop(mcx->io, qp);
	if (qp->ra->backlog > 0)
	    qp->ra->backlog--;
	RB_search_and_delete(mcx->retransmit, qp);
	RB_delete(mcx->retransmit_by_app_ctx, r);
	av_free(qp->ac);
    } else
	RB_search_and_delete(mcx->outgoing, &q);
    av_free(q.ac);
    return MAVIS_FINAL;
}

static void retransmit(struct query *q, int fd __attribute__((unused)))
{
    struct remote_addr_s *rat, *ra = q->ra;
    if (ra->backlog > 0)
	ra->backlog--;
    Debug((DEBUG_PROC, "retransmit-counter is at %d\n", q->tries + 1));
    Debug((DEBUG_PROC, "               max is at %d\n", q->mcx->tries));
    if (++q->tries == q->mcx->tries) {
	rb_node_t *r;
	if ((r = RB_search(q->mcx->retransmit, q))) {
	    rb_tree_t *out;
	    struct query *qp = RB_payload(r, struct query *);
	    io_sched_pop(qp->mcx->io, qp);
	    if (qp->ra->backlog > 0)
		qp->ra->backlog--;
	    RB_search_and_delete(q->mcx->retransmit_by_app_ctx, qp);
	    RB_delete(qp->mcx->retransmit, r);
	    q->result = MAVIS_TIMEOUT;
	    out = qp->mcx->outgoing;
	    RB_insert(out, qp);
	    while ((r = RB_first(out))) {
		qp = RB_payload(r, struct query *);
		((void (*)(void *)) qp->ac->app_cb) (qp->ac->app_ctx);
	    }
	}
    } else {
	io_sched_renew(q->mcx->io, q);
	for (ra = rat = q->mcx->remote_addr; rat; rat = rat->next)
	    if (ra->backlog > rat->backlog)
		ra = rat;
	q->ra = ra;
	ra->count_s++, ra->count_s_p++;
	if (MAVIS_DEFERRED == av_send(q->ac, q->mcx->sock, &ra->sa, ra->blowfish))
	    ra->backlog++;
    }
}

#define HAVE_mavis_send_in
static int mavis_send_in(mavis_ctx * mcx, av_ctx ** ac)
{
    struct remote_addr_s *ra, *rat;
    DebugIn(DEBUG_MAVIS);
    if (!strcasecmp(av_get(*ac, AV_A_TYPE), AV_V_TYPE_LOGSTATS)) {
	unsigned long long count_s = 0;
	unsigned long long count_r = 0;
	unsigned long long count_s_p = 0;
	unsigned long long count_r_p = 0;
	u_long backlog_max = 0;
	u_long backlog_max_p = 0;
	for (rat = mcx->remote_addr; rat; rat = rat->next) {
	    char buf[INET6_ADDRSTRLEN];
	    su_ntop(&rat->sa, buf, (socklen_t) sizeof(buf));
	    logmsg
		("STAT %s: [%s]:%d O=%llu I=%llu B=%lu "
		 "o=%llu i=%llu b=%lu", MAVIS_name, buf,
		 su_get_port(&rat->sa), rat->count_s, rat->count_r, rat->backlog_max, rat->count_s_p, rat->count_r_p, rat->backlog_max_p);
	    count_s += rat->count_s;
	    count_r += rat->count_r;
	    backlog_max += rat->backlog_max;
	    count_s_p += rat->count_s_p;
	    count_r_p += rat->count_r_p;
	    backlog_max_p += rat->backlog_max_p;
	    rat->backlog_max_p = rat->backlog;
	}

	logmsg
	    ("STAT %s:  O=%llu I=%llu B=%lu T=" TIME_T_PRINTF
	     " o=%lld i=%llu b=%lu t=" TIME_T_PRINTF,
	     MAVIS_name, count_s, count_r,
	     backlog_max, io_now.tv_sec - mcx->startup_time, count_s_p, count_r_p, backlog_max_p, io_now.tv_sec - mcx->lastdump);
	mcx->lastdump = time(NULL);
	return MAVIS_DOWN;
    }

/*
 * Periodically try to rebalance (and reactivate) peers by resetting
 * all backlog values to 0.
 */
    if (mcx->rebalance && ++mcx->request_count > mcx->rebalance)
	for (mcx->request_count = 0, rat = mcx->remote_addr; rat; rat = rat->next)
	    rat->backlog = 0;
    if (mcx->io) {
	int result;
	for (ra = rat = mcx->remote_addr; rat; rat = rat->next)
	    if (ra->backlog > rat->backlog)
		ra = rat;
	if (ra) {
	    ra->count_s++, ra->count_s_p++;
	    result = av_send(*ac, mcx->sock, &ra->sa, ra->blowfish);
	    if (result == MAVIS_DEFERRED) {
		struct query *q = Xcalloc(1, sizeof(struct query));
		char *serial = av_get(*ac, AV_A_SERIAL);
		q->mcx = mcx;
		q->ra = ra;
		q->ac = *ac;
		if (mcx->ac_bak) {
		    q->ac_bak = mcx->ac_bak;
		    mcx->ac_bak = NULL;
		}
		*ac = NULL;
		q->serial_crc = crc32_update(INITCRC32, (u_char *) serial, strlen(serial));
		io_sched_add(mcx->io, q, (void *) retransmit, mcx->timeout, 0);
		RB_insert(mcx->retransmit, q);
		RB_insert(mcx->retransmit_by_app_ctx, q);
		ra->backlog++;
		if (ra->backlog_max < ra->backlog)
		    ra->backlog_max = ra->backlog;
		if (ra->backlog_max_p < ra->backlog)
		    ra->backlog_max_p = ra->backlog;
	    }
	} else {
	    logmsg("Warning: no remote connection endpoint available");
	    result = MAVIS_IGNORE;
	}

	Debug((DEBUG_MAVIS, "- %s = %d (async)\n", __func__, result));
	return result;
    } else {
	int tries = mcx->tries;
	char *v = NULL;
	struct pollfd ufds[1];
	char *serial = av_get(*ac, AV_A_SERIAL);
	av_ctx *avc = av_new(NULL, NULL);
	ufds[0].fd = mcx->sock;
	ufds[0].events = POLLIN;
	do {
	    sockaddr_union sa;
	    for (ra = rat = mcx->remote_addr; rat; rat = rat->next)
		if (ra->backlog > rat->backlog)
		    ra = rat;
	    if ((!tries && mcx->tries)
		|| (ra->backlog++, MAVIS_FINAL == av_send(*ac, mcx->sock, &ra->sa, ra->blowfish))) {
		av_set(*ac, AV_A_RESULT, AV_V_RESULT_ERROR);
		av_set(*ac, AV_A_COMMENT, "timed out");
		Debug((DEBUG_MAVIS, "- %s = 0 (sync)\n", __func__));
		return MAVIS_TIMEOUT;
	    }

	    tries--;
	    if ((1 != poll(ufds, 1, mcx->timeout * 1000))
		|| (!(ufds[0].revents & POLLIN))
		|| (ra != av_recv(mcx, avc, mcx->sock, &sa))
		|| (!(v = av_get(avc, AV_A_SERIAL))))
		continue;
	    if (ra) {
		if (ra->backlog > 0)
		    ra->backlog--;
		ra->count_r++, ra->count_r_p++;
	    }
	}
	while (!v || strcmp(serial, v)
	       || !av_get(avc, AV_A_RESULT));
	av_move(*ac, avc);
	av_free(avc);
	Debug((DEBUG_MAVIS, "- %s = 0 (sync)\n", __func__));
	return MAVIS_FINAL;
    }
}

static void mavis_io(mavis_ctx * mcx, int cur __attribute__((unused)))
{
    struct remote_addr_s *ra;
    sockaddr_union sa;
    av_ctx *ac = av_new(NULL, NULL);
    DebugIn(DEBUG_MAVIS);
    if ((ra = av_recv(mcx, ac, mcx->sock, &sa))) {
	struct query q;
	char *serial;
	if ((serial = av_get(ac, AV_A_SERIAL))) {
	    rb_node_t *r;
	    q.serial_crc = crc32_update(INITCRC32, (u_char *) serial, strlen(serial));
	    q.ac = ac;
	    r = RB_search(mcx->retransmit, &q);
	    q.ac = NULL;
	    if (r) {
		struct query *qp = RB_payload(r, struct query *);
		io_sched_pop(mcx->io, qp);
		RB_search_and_delete(mcx->retransmit_by_app_ctx, qp);
		RB_delete(mcx->retransmit, r);
		av_move(qp->ac, ac);
		RB_insert(mcx->outgoing, qp);
		if (ra->backlog > 0)
		    ra->backlog--;
		qp->result = MAVIS_FINAL;
		Debug((DEBUG_MAVIS, "%s:%d\n", __FILE__, __LINE__));
		while ((r = RB_first(mcx->outgoing))) {
		    qp = RB_payload(r, struct query *);
		    if (mcx->ac_bak)
			av_free(mcx->ac_bak);
		    mcx->ac_bak = qp->ac_bak;
		    qp->ac_bak = NULL;
		    ((void (*)(void *)) qp->ac->app_cb) (qp->ac->app_ctx);
		}
	    }
	}
    } else {
	char buf[INET6_ADDRSTRLEN];
	logmsg("Alert: reply from unknown peer %s:%u", su_ntop(&sa, buf, (socklen_t) sizeof(buf)), (u_int) su_get_port(&sa));
    }
    av_free(ac);
    DebugOut(DEBUG_MAVIS);
}

#define HAVE_mavis_recv_in
static int mavis_recv_in(mavis_ctx * mcx, av_ctx ** ac, void *app_ctx)
{
    struct query q;
    rb_node_t *r;
    int result = MAVIS_DOWN;
    DebugIn(DEBUG_MAVIS);
    q.ac = av_new(NULL, app_ctx);
    r = RB_search(mcx->outgoing, &q);
    av_free(q.ac);
    if (r) {
	struct query *qp = RB_payload(r, struct query *);
	result = qp->result;
	mcx->last_result = result;
	*ac = qp->ac;
	av_set(*ac, AV_A_CURRENT_MODULE, mcx->identifier);
	qp->ac = NULL;
	RB_delete(mcx->outgoing, r);
	result = mavis_send(mcx->top, ac);
	if (result == MAVIS_FINAL)
	    result = MAVIS_FINAL_DEFERRED;
    }

    DebugOut(DEBUG_MAVIS);
    return result;
}

#define HAVE_mavis_new
static void mavis_new(mavis_ctx * mcx)
{
    mcx->sock = -1;
    mcx->timeout = 5;
    mcx->tries = 6;
}

#include "mavis_glue.c"
