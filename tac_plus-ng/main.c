/*
   Copyright (C) 1999-2022 Marc Huber (Marc.Huber@web.de)
   All rights reserved.

   Redistribution and use in source and binary  forms,  with or without
   modification, are permitted provided  that  the following conditions
   are met:

   1. Redistributions of source code  must  retain  the above copyright
      notice, this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions  and  the following disclaimer in
      the  documentation  and/or  other  materials  provided  with  the
      distribution.

   3. The end-user documentation  included with the redistribution,  if
      any, must include the following acknowledgment:

          This product includes software developed by Marc Huber
	  (Marc.Huber@web.de).

      Alternately,  this  acknowledgment  may  appear  in  the software
      itself, if and wherever such third-party acknowledgments normally
      appear.

   THIS SOFTWARE IS  PROVIDED  ``AS IS''  AND  ANY EXPRESSED OR IMPLIED
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
   IN NO EVENT SHALL  ITS  AUTHOR  BE  LIABLE FOR ANY DIRECT, INDIRECT,
   INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
   BUT NOT LIMITED  TO,  PROCUREMENT OF  SUBSTITUTE  GOODS OR SERVICES;
   LOSS OF USE,  DATA,  OR PROFITS;  OR  BUSINESS INTERRUPTION) HOWEVER
   CAUSED AND ON ANY THEORY OF LIABILITY,  WHETHER IN CONTRACT,  STRICT
   LIABILITY,  OR TORT  (INCLUDING NEGLIGENCE OR OTHERWISE)  ARISING IN
   ANY WAY OUT OF THE  USE  OF  THIS  SOFTWARE,  EVEN IF ADVISED OF THE
   POSSIBILITY OF SUCH DAMAGE.
 */

#include "headers.h"
#include "misc/version.h"
#include <sys/resource.h>
#include <signal.h>
#include <netinet/tcp.h>
#include "misc/buffer.h"
#include "misc/strops.h"
#include "mavis/log.h"

#ifdef VRF_BINDTODEVICE
#include <net/if.h>
#endif
#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

#ifdef WITH_SSL
#include <openssl/x509v3.h>
#include <openssl/err.h>
#endif

static const char rcsid[] __attribute__((used)) = "$Id$";

struct config config = { 0 };	/* configuration data */

static void die(int signum)
{
    report(NULL, LOG_INFO, ~0, "Received signal %d, shutting down.", signum);
    tac_exit(EX_OK);
}

int die_when_idle = 0;
static struct context *ctx_spawnd = NULL;

static void cleanup_spawnd(struct context *ctx __attribute__((unused)), int cur __attribute__((unused)))
{
    if (ctx_spawnd) {
	io_close(ctx->io, ctx_spawnd->sock);
	ctx_spawnd = NULL;
    }

    if (common_data.users_cur == 0 /*&& logs_flushed(config.default_realm) FIXME */ ) {
	drop_mcx(config.default_realm);
	if (!(common_data.debug & DEBUG_TACTRACE_FLAG))
	    report(NULL, LOG_INFO, ~0, "Exiting.");
	exit(EX_OK);
    }

    die_when_idle = -1;
    set_proctitle(ACCEPT_NEVER);
}

static int compare_session(const void *a, const void *b)
{
    return ((tac_session *) a)->session_id - ((tac_session *) b)->session_id;
}

static u_int context_id = 0;

static struct context *ctx_lru_first = NULL;
static struct context *ctx_lru_last = NULL;

static void context_lru_remove(struct context *ctx)
{
    if (ctx->lru_prev)
	ctx->lru_prev->lru_next = ctx->lru_next;

    if (ctx->lru_next)
	ctx->lru_next->lru_prev = ctx->lru_prev;

    if (ctx == ctx_lru_first)
	ctx_lru_first = ctx->lru_next;

    if (ctx == ctx_lru_last)
	ctx_lru_last = ctx->lru_prev;

    ctx->lru_prev = ctx->lru_next = NULL;
}

void context_lru_append(struct context *ctx)
{
    if (ctx == ctx_lru_first || ctx->lru_prev)
	context_lru_remove(ctx);
    ctx->lru_prev = ctx_lru_last;
    if (ctx_lru_last)
	ctx_lru_last->lru_next = ctx;
    if (!ctx_lru_first)
	ctx_lru_first = ctx;
    ctx_lru_last = ctx;
    ctx->lru_next = NULL;
}

struct scm_data_accept_ext {
    tac_realm *realm;
    size_t vrf_len;
    char vrf[IFNAMSIZ + 1];
    union {
	struct scm_data_accept sd;
	struct scm_data_udp sd_udp;
    };
};

struct context_px {
    int sock;			/* socket for this connection */
    int type;
    io_context_t *io;
    time_t last_io;
    struct context_px *lru_prev;
    struct context_px *lru_next;
    struct scm_data_accept_ext sd;
};

static void cleanup_px(struct context_px *, int);

static struct context_px *ctx_px_lru_first = NULL;
static struct context_px *ctx_px_lru_last = NULL;

static void context_px_lru_remove(struct context_px *ctx)
{
    if (ctx->lru_prev)
	ctx->lru_prev->lru_next = ctx->lru_next;

    if (ctx->lru_next)
	ctx->lru_next->lru_prev = ctx->lru_prev;

    if (ctx == ctx_px_lru_first)
	ctx_px_lru_first = ctx->lru_next;

    if (ctx == ctx_px_lru_last)
	ctx_px_lru_last = ctx->lru_prev;

    ctx->lru_prev = ctx->lru_next = NULL;
}

void context_px_lru_append(struct context_px *ctx)
{
    if (ctx == ctx_px_lru_first || ctx->lru_prev)
	context_px_lru_remove(ctx);
    ctx->lru_prev = ctx_px_lru_last;
    if (ctx_px_lru_last)
	ctx_px_lru_last->lru_next = ctx;
    if (!ctx_px_lru_first)
	ctx_px_lru_first = ctx;
    ctx_px_lru_last = ctx;
    ctx->lru_next = NULL;
}

static void users_inc(void)
{
    if ((ctx_lru_first || ctx_px_lru_first) && config.ctx_lru_threshold && (common_data.users_cur == config.ctx_lru_threshold)) {
	time_t last = 0, last_px = 0;
	if (ctx_lru_first)
	    last = ctx_lru_first->last_io;
	if (ctx_px_lru_first)
	    last_px = ctx_px_lru_first->last_io;

	if ((last && (last < last_px)) || !ctx_px_lru_first) {
	    struct context *ctx = ctx_lru_first;
	    context_lru_remove(ctx);
	    io_sched_add(common_data.io, ctx, (void *) cleanup, 0, 0);
	} else {
	    struct context_px *ctx = ctx_px_lru_first;
	    context_px_lru_remove(ctx);
	    io_sched_add(common_data.io, ctx, (void *) cleanup_px, 0, 0);
	}
    }
    common_data.users_cur++;
    set_proctitle(die_when_idle ? ACCEPT_NEVER : ACCEPT_YES);
}

void users_dec(void)
{
    static int pending = 0;
    pending++;
    common_data.users_cur--;
    struct scm_data d = {.type = SCM_DONE,.count = pending };
    if (ctx_spawnd && (common_data.scm_send_msg(ctx_spawnd->sock, &d, -1) < 0)) {
	if (errno != EAGAIN && errno != EWOULDBLOCK)
	    die_when_idle = 1;
    } else
	pending = 0;
    set_proctitle(die_when_idle ? ACCEPT_NEVER : ACCEPT_YES);
}

struct context *new_context(struct io_context *io, tac_realm *r)
{
    mem_t *mem = mem_create(M_POOL);
    struct context *c = mem_alloc(mem, sizeof(struct context));
    c->io = io;
    c->sock = -1;
    c->mem = mem;
    c->hint = "";
    if (r) {
	c->sessions = RB_tree_new(compare_session, NULL);
	c->id = context_id++;
	c->realm = r;
	c->debug = r->debug;
    } else {
	c->debug = common_data.debug;
    }
    return c;
}

static sigset_t master_set;
static void process_signals(void)
{
    sigprocmask(SIG_UNBLOCK, &master_set, NULL);
    sigprocmask(SIG_SETMASK, &master_set, NULL);
}

#ifdef WITH_DNS
static void expire_dns(tac_realm *r)
{
    /* purge old DNS cache */
    if (r->dnspurge_last + r->dns_caching_period < io_now.tv_sec) {
	r->dnspurge_last = io_now.tv_sec;
	if (r->dns_tree_ptr[2])
	    radix_drop(&r->dns_tree_ptr[2], NULL);
	r->dns_tree_ptr[2] = r->dns_tree_ptr[1];
	r->dns_tree_ptr[1] = NULL;
    }
    if (r->realms) {
	for (rb_node_t * rbn = RB_first(r->realms); rbn; rbn = RB_next(rbn))
	    expire_dns(RB_payload(rbn, tac_realm *));
    }
}
#endif

static void periodics(struct context *ctx, int cur __attribute__((unused)))
{
    io_sched_renew_proc(ctx->io, ctx, (void *) periodics);
    process_signals();
    io_child_reap();

    if (!die_when_idle) {
	if (config.suicide && (config.suicide < io_now.tv_sec)) {
	    report(NULL, LOG_INFO, ~0, "Retire timeout is up. Told parent about this.");
	    struct scm_data sd = {.type = SCM_DYING };
	    if (ctx_spawnd)
		common_data.scm_send_msg(ctx_spawnd->sock, &sd, -1);
	    die_when_idle = -1;
	} else {
	    struct scm_data sd = {.type = SCM_KEEPALIVE };
	    if (ctx_spawnd && common_data.scm_send_msg(ctx_spawnd->sock, &sd, -1) && errno != EAGAIN && errno != EWOULDBLOCK)
		die_when_idle = -1;
	}
    }

    if (die_when_idle)
	cleanup_spawnd(ctx, -1 /* unused */ );

    expire_dynamic_users(config.default_realm);

#ifdef WITH_DNS
    expire_dns(config.default_realm);
#endif
}

static void periodics_ctx(struct context *ctx, int cur __attribute__((unused)))
{
    if (!ctx->out && !ctx->delayed && (ctx->host->tcp_timeout || ctx->dying) && (ctx->last_io + ctx->host->tcp_timeout < io_now.tv_sec)) {
	cleanup(ctx, ctx->sock);
	return;
    }

    if (!ctx->out && !ctx->delayed && (ctx->host->udp_timeout || ctx->dying) && (ctx->last_io + ctx->host->udp_timeout < io_now.tv_sec)) {
	cleanup(ctx, ctx->sock);
	return;
    }

    for (rb_node_t * rbnext, *rbn = RB_first(ctx->sessions); rbn; rbn = rbnext) {
	tac_session *s = RB_payload(rbn, tac_session *);
	rbnext = RB_next(rbn);
	if (s->session_timeout < io_now.tv_sec)
	    cleanup_session(s);
    }

    tac_script_expire_exec_context(ctx);

    if (ctx->cleanup_when_idle && !ctx->out && !ctx->delayed && !RB_first(ctx->sessions) && !RB_first(ctx->shellctxcache))
	cleanup(ctx, ctx->sock);
    else
	io_sched_renew_proc(ctx->io, ctx, (void *) periodics_ctx);
}

static void accept_control(struct context *, int __attribute__((unused)));
static void accept_control_final(struct context *);
static void accept_control_common(int, struct scm_data_accept_ext *, sockaddr_union *, u_char *, size_t);
static void accept_control_singleprocess(int, struct scm_data_accept *);
static void accept_control_udp_singleprocess(int s, struct scm_data_udp *sd);
static void accept_control_raw(int, struct scm_data_accept_ext *);
static void accept_control_px(int, struct scm_data_accept_ext *);
static void accept_control_check_tls(struct context *, int);
#if defined(WITH_SSL)
static void accept_control_tls(struct context *, int);
#endif
static void setup_signals(void);

int main(int argc, char **argv, char **envp)
{
    scm_main(argc, argv, envp);

    cfg_init();

    buffer_setsize(0x8000, 0x10);

    if (!common_data.conffile) {
	common_data.conffile = argv[optind];
	common_data.id = argv[optind + 1];
    }
    if (!common_data.io)
	common_data.io = io_init();
    cfg_read_config(common_data.conffile, parse_decls, common_data.id ? common_data.id : common_data.progname);
    complete_realm(config.default_realm);

    if (common_data.parse_only)
	tac_exit(EX_OK);

    signal(SIGTERM, die);
    signal(SIGPIPE, SIG_IGN);

    if (common_data.debug & DEBUG_TACTRACE_FLAG)
	fprintf(stderr, "Version: " VERSION "\n");
    else
	report(NULL, LOG_INFO, ~0, "Version " VERSION " initialized");

    umask(022);

    mavis_detach();

    setup_sig_segv(common_data.coredumpdir, common_data.gcorepath, common_data.debug_cmd);

    if (common_data.singleprocess) {
	common_data.scm_accept = accept_control_singleprocess;
	common_data.scm_udpdata = accept_control_udp_singleprocess;
    } else {
	setproctitle_init(argv, envp);
	setup_signals();
	ctx_spawnd = new_context(common_data.io, NULL);
	ctx_spawnd->sock = dup(0);
	dup2(2, 0);
	fcntl(ctx_spawnd->sock, F_SETFL, O_NONBLOCK);
	io_register(common_data.io, ctx_spawnd->sock, ctx_spawnd);
	io_set_cb_i(common_data.io, ctx_spawnd->sock, (void *) accept_control);
	io_clr_cb_o(common_data.io, ctx_spawnd->sock);
	io_set_cb_h(common_data.io, ctx_spawnd->sock, (void *) cleanup_spawnd);
	io_set_cb_e(common_data.io, ctx_spawnd->sock, (void *) cleanup_spawnd);
	io_set_i(common_data.io, ctx_spawnd->sock);
    }

    if (ctx_spawnd) {
	struct scm_data sd = {.type = SCM_MAX,.count = io_get_nfds_limit(common_data.io) / 4 };
	common_data.scm_send_msg(ctx_spawnd->sock, (struct scm_data *) &sd, -1);
    }

    io_sched_add(common_data.io, new_context(common_data.io, NULL), (void *) periodics, common_data.cleanup_interval, 0);

    init_mcx(config.default_realm);
    authen_init();

    set_proctitle(ACCEPT_YES);
    io_main(common_data.io);
}

#ifdef WITH_SSL
void update_bio(struct context *ctx)
{
    if (ctx->rbio) {
	char buf[8192];
	ssize_t len = read(ctx->sock, buf, sizeof(buf));
	if (len > 0)
	    BIO_write(ctx->rbio, buf, len);
    }
}
#endif

void cleanup(struct context *ctx, int cur __attribute__((unused)))
{
#ifdef WITH_SSL
    if (ctx->tls) {
	if (!ctx->reset_tcp) {
	    update_bio(ctx);
	    int res = io_SSL_shutdown(ctx->tls, ctx->io, ctx->sock, cleanup);
	    if (res < 0 && errno == EAGAIN)
		return;
	}
	SSL_free(ctx->tls);
	ctx->tls = NULL;
    }
#endif

    if (!ctx->msgid) {
#define STATICSTR(A,B) \
static str_t conn_ ## A = { .txt = #A, .len = sizeof(#A) - 1 }; \
static str_t msgid_ ## A = { .txt = B, .len = sizeof(B) - 1 }

	STATICSTR(stop, "CONN-STOP");
	ctx->msgid = &msgid_stop;
	ctx->acct_type = &conn_stop;
    }

    log_exec(NULL, ctx, S_connection, io_now.tv_sec);

    io_sched_drop(ctx->io, ctx);
    if (ctx->reset_tcp) {
	struct linger linger = {.l_onoff = 1 };;
	setsockopt(ctx->sock, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger));
    }
    io_close(ctx->io, ctx->sock);
    ctx->sock = -1;

    for (rb_node_t * u, *t = RB_first(ctx->sessions); t; t = u) {
	u = RB_next(t);
	cleanup_session(RB_payload(t, tac_session *));
    }

    if (ctx->sessions)
	RB_tree_delete(ctx->sessions);

    if (ctx->shellctxcache)
	RB_tree_delete(ctx->shellctxcache);

#ifdef WITH_DNS
    if (ctx->revmap_pending) {
	tac_realm *r = ctx->realm;
	while (r && !r->idc)
	    r = r->parent;
	if (r)
	    io_dns_cancel(r->idc, ctx);
    }
#endif
    if (ctx->mavis_pending) {
	mavis_ctx *mcx = lookup_mcx(ctx->realm);
	if (mcx)
	    mavis_cancel(mcx, ctx);
    }

    users_dec();
    context_lru_remove(ctx);
    mem_destroy(ctx->mem);

    if (common_data.debug & DEBUG_TACTRACE_FLAG)
	die_when_idle = 1;

    if (ctx_spawnd && die_when_idle)
	cleanup_spawnd(ctx_spawnd, 0);
}

// Proxy structs from Willy Tarreau/HAProxy Technologies
// https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt

struct proxy_hdr_v2 {
    uint8_t sig[12];		/* hex 0D 0A 0D 0A 00 0D 0A 51 55 49 54 0A */
    uint8_t ver_cmd;		/* protocol version and command */
    uint8_t fam;		/* protocol family and address */
    uint16_t len;		/* number of following bytes part of the header */
} __attribute__((__packed__));

union proxy_addr {
    struct {			/* for TCP/UDP over IPv4, len = 12 */
	uint32_t src_addr;
	uint32_t dst_addr;
	uint16_t src_port;
	uint16_t dst_port;
    } ipv4_addr;
    struct {			/* for TCP/UDP over IPv6, len = 36 */
	uint8_t src_addr[16];
	uint8_t dst_addr[16];
	uint16_t src_port;
	uint16_t dst_port;
    } ipv6_addr;
    struct {			/* for AF_UNIX sockets, len = 216 */
	uint8_t src_addr[108];
	uint8_t dst_addr[108];
    } unix_addr;
} __attribute__((__packed__));

//

static void cleanup_px(struct context_px *ctx, int cur)
{
    io_sched_drop(ctx->io, ctx);
    io_close(ctx->io, ctx->sock);
    ctx->sock = -1;

    users_dec();
    context_px_lru_remove(ctx);
    free(ctx);

    if (ctx_spawnd && die_when_idle)
	cleanup_spawnd(ctx_spawnd, cur);
}

static void try_raw(struct context_px *ctx, int cur __attribute__((unused)))
{
    io_sched_drop(ctx->io, ctx);
    io_unregister(ctx->io, ctx->sock);
    accept_control_raw(ctx->sock, &ctx->sd);
    free(ctx);
}

static void catchhup(int i __attribute__((unused)))
{
    signal(SIGHUP, SIG_IGN);
    signal(SIGTERM, SIG_IGN);

    if (ctx_spawnd)
	cleanup_spawnd(ctx_spawnd, ctx_spawnd->sock);
    die_when_idle = -1;
    report(NULL, LOG_INFO, ~0, "SIGHUP: No longer accepting new connections.");
}

static void setup_signals()
{
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, catchhup);
    signal(SIGTERM, catchhup);
    sigfillset(&master_set);
    sigdelset(&master_set, SIGSEGV);
    sigprocmask(SIG_SETMASK, &master_set, NULL);
}

static tac_realm *set_sd_realm(int, struct scm_data_accept_ext *);

static void accept_control_singleprocess(int s, struct scm_data_accept *sd)
{
    struct scm_data_accept_ext sd_ext = {.sd = *sd };
    tac_realm *r = set_sd_realm(-1, &sd_ext);
    users_inc();
    if ((sd->flags & SCM_FLAG_HAPROXY) || r->haproxy_autodetect == TRISTATE_YES)
	accept_control_px(s, &sd_ext);
    else
	accept_control_raw(s, &sd_ext);
}

static void accept_control_udp_singleprocess(int s, struct scm_data_udp *sd)
{
    struct scm_data_accept_ext sd_ext = {.sd_udp = *sd };
    set_sd_realm(-1, &sd_ext);
    users_inc();
    accept_control_common(s, &sd_ext, NULL, sd->data, sd->data_len);
}

static void accept_control_raw(int s, struct scm_data_accept_ext *sd)
{
    accept_control_common(s, sd, NULL, NULL, 0);
}

static struct context_px *new_context_px(struct io_context *io, struct scm_data_accept_ext *sd)
{
    struct context_px *c = calloc(1, sizeof(struct context_px));
    c->io = io;
    memcpy(&c->sd, sd, sizeof(*sd));
    return c;
}

static void read_px(struct context_px *ctx, int cur)
{
    char tmp[240] = { 0 };
    struct proxy_hdr_v2 *hdr = (struct proxy_hdr_v2 *) tmp;
    union proxy_addr *addr = (union proxy_addr *) &tmp[sizeof(struct proxy_hdr_v2)];
    ssize_t len = recv(cur, &tmp, sizeof(tmp), MSG_PEEK);
    ctx->last_io = io_now.tv_sec;
    uint16_t hlen;
    if ((len < (ssize_t) sizeof(struct proxy_hdr_v2))
	|| ((hdr->ver_cmd >> 4) != 2)
	|| (memcmp(hdr->sig, "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A", 12))
	|| ((uint16_t) len < (hlen = ntohs(hdr->len)) + sizeof(struct proxy_hdr_v2))
	|| (hdr->fam == 0x11 && hlen < 12)
	|| (hdr->fam == 0x21 && hlen < 36)) {
	if (ctx->sd.realm->haproxy_autodetect == TRISTATE_YES)
	    try_raw(ctx, cur);
	else
	    cleanup_px(ctx, cur);
	return;
    }
    UNUSED_RESULT(read(cur, &tmp, sizeof(struct proxy_hdr_v2) + hlen));

    sockaddr_union from = { 0 };
    switch (hdr->fam) {
    case 0x11:
	from.sin.sin_family = AF_INET;
	from.sin.sin_addr.s_addr = addr->ipv4_addr.src_addr;
	from.sin.sin_port = addr->ipv4_addr.src_port;
	break;
    case 0x21:
	from.sin6.sin6_family = AF_INET6;
	from.sin6.sin6_port = addr->ipv6_addr.dst_port;
	memcpy(&from.sin6.sin6_addr, addr->ipv6_addr.src_addr, 16);
	break;
    case 0x00:
	try_raw(ctx, cur);
	return;
    default:
	cleanup_px(ctx, cur);
	return;
    }

    io_sched_drop(ctx->io, ctx);
    io_unregister(ctx->io, ctx->sock);
    accept_control_common(ctx->sock, &ctx->sd, &from, NULL, 0);
    free(ctx);
}

static void reject_conn(struct context *ctx, const char *hint, char *tls, int line)
{
    if (!hint)
	hint = "";
    char *prehint = "", *posthint = "";
    if (*hint)
	prehint = " (", posthint = ")";

    if (ctx->proxy_addr_ascii.txt) {
	if (!(common_data.debug & DEBUG_TACTRACE_FLAG))
	    report(NULL, LOG_INFO, ~0, "proxied %sconnection request from %s for %s to %s port %s (realm: %s%s%s) rejected%s%s%s [%d]",
		   tls, ctx->proxy_addr_ascii.txt, ctx->peer_addr_ascii.txt,
		   ctx->server_addr_ascii.txt, ctx->server_port_ascii.txt, ctx->realm->name.txt, ctx->vrf.txt ? ", vrf: " : "",
		   ctx->vrf.txt ? ctx->vrf.txt : "", prehint, hint, posthint, line);
    } else
	report(NULL, LOG_INFO, ~0, "%sconnection request from %s to %s port %s (realm: %s%s%s) rejected%s%s%s [%d]",
	       tls, ctx->peer_addr_ascii.txt,
	       ctx->server_addr_ascii.txt, ctx->server_port_ascii.txt, ctx->realm->name.txt, ctx->vrf.txt ? ", vrf: " : "", ctx->vrf.txt ? ctx->vrf.txt : "",
	       prehint, hint, posthint, line);

    STATICSTR(reject, "CONN-REJECT");

    ctx->msgid = &msgid_reject;
    ctx->acct_type = &conn_reject;

    ctx->reset_tcp = BISTATE_YES;
    cleanup(ctx, ctx->sock);
}

void complete_host(tac_host *);

#if defined(WITH_SSL)
static int query_mavis_host(struct context *, void (*)(struct context *));

static void complete_host_mavis_tls(struct context *ctx)
{
    if (query_mavis_host(ctx, complete_host_mavis_tls))
	return;

    if (ctx->mavis_result == S_deny) {
	reject_conn(ctx, ctx->hint, "by MAVIS backend", __LINE__);
	return;
    }
    accept_control_final(ctx);
}

static void set_host_by_dn(struct context *ctx, char *t)
{
    while (t) {
	tac_host *h = lookup_host(t, ctx->realm);
	if (h) {
	    ctx->host = h;
	    return;
	}
	t = strchr(t, '.');
	if (t)
	    t++;
    }
}

#ifndef OPENSSL_NO_PSK
static void set_host_by_psk_identity(struct context *ctx, char *t)
{
    char *at = strchr(t, '@');
    if (at) {
	ctx->host = lookup_host(t, ctx->realm);
	if (ctx->host)
	    return;
	t = at + 1;
    }
    set_host_by_dn(ctx, t);
}
#endif

static void accept_control_tls(struct context *ctx, int cur)
{
    const char *hint = "";
    io_clr_i(ctx->io, cur);
    io_clr_o(ctx->io, cur);

    ctx->last_io = io_now.tv_sec;

    update_bio(ctx);
    int r = SSL_accept(ctx->tls);
    switch (r) {
    default:
	switch (SSL_get_error(ctx->tls, r)) {
	case SSL_ERROR_WANT_READ:
	    io_set_i(ctx->io, cur);
	    if (SSL_want_write(ctx->tls))
		io_set_o(ctx->io, cur);
	    return;
	case SSL_ERROR_WANT_WRITE:
	    io_set_o(ctx->io, cur);
	    if (SSL_want_read(ctx->tls))
		io_set_i(ctx->io, cur);
	    return;
	default:
	    hint = (ctx->hint && *ctx->hint) ? ctx->hint : ERR_error_string(ERR_get_error(), NULL);
	    reject_conn(ctx, hint, "TLS ", __LINE__);
	    return;
	}
    case 0:
	hint = ERR_error_string(ERR_get_error(), NULL);
	reject_conn(ctx, hint, "TLS ", __LINE__);
	return;
    case 1:
	break;
    }

    if (ctx->alpn_passed == TRISTATE_NO) {
	reject_conn(ctx, "ALPN", "TLS ", __LINE__);
	return;
    }
    if (ctx->sni_passed != BISTATE_YES) {
	reject_conn(ctx, "SNI", "TLS ", __LINE__);
	return;
    }

    tac_host *by_address = ctx->host;
    ctx->host = NULL;

#ifndef OPENSSL_NO_PSK
    if (ctx->tls_psk_identity.txt) {
	set_host_by_psk_identity(ctx, ctx->tls_psk_identity.txt);
	goto done;
    }
#endif
    X509 *cert = SSL_get_peer_certificate(ctx->tls);

    if (cert) {
	char buf[40];
	time_t notafter = -1, notbefore = -1;

	str_set(&ctx->tls_conn_version, (char *) SSL_get_version(ctx->tls), 0);
	str_set(&ctx->tls_conn_cipher, (char *) SSL_get_cipher(ctx->tls), 0);
	snprintf(buf, sizeof(buf), "%d", SSL_get_cipher_bits(ctx->tls, NULL));
	str_set(&ctx->tls_conn_cipher_strength, mem_strdup(ctx->mem, buf), 0);

	{
	    char buf[512];
	    ASN1_TIME *notafter_asn1 = X509_get_notAfter(cert);
	    ASN1_TIME *notbefore_asn1 = X509_get_notBefore(cert);
	    X509_NAME *x;

	    if ((x = X509_get_subject_name(cert))) {
		char *t = X509_NAME_oneline(x, buf, sizeof(buf));
		if (t)
		    str_set(&ctx->tls_peer_cert_subject, mem_strdup(ctx->mem, t), 0);
	    }
	    if ((x = X509_get_issuer_name(cert))) {
		char *t = X509_NAME_oneline(x, buf, sizeof(buf));
		if (t)
		    str_set(&ctx->tls_peer_cert_issuer, mem_strdup(ctx->mem, t), 0);
	    }

	    if (notafter_asn1 && notbefore_asn1) {
		struct tm notafter_tm, notbefore_tm;
		if ((1 == ASN1_TIME_to_tm(notafter_asn1, &notafter_tm)) && (1 == ASN1_TIME_to_tm(notbefore_asn1, &notbefore_tm))) {
		    notafter = mktime(&notafter_tm);
		    notbefore = mktime(&notbefore_tm);
		}
	    }
	}

	if (ctx->tls_peer_cert_subject.txt) {
	    while (*ctx->tls_peer_cert_subject.txt == '/')
		ctx->tls_peer_cert_subject.txt++;
	    ctx->tls_peer_cert_subject.len = strlen(ctx->tls_peer_cert_subject.txt);
	}
	if (ctx->tls_peer_cert_issuer.txt) {
	    while (*ctx->tls_peer_cert_issuer.txt == '/')
		ctx->tls_peer_cert_issuer.txt++;
	    ctx->tls_peer_cert_issuer.len = strlen(ctx->tls_peer_cert_issuer.txt);
	}
	if (notafter > -1 && notbefore > -1 && ctx->realm->tls_accept_expired != TRISTATE_YES && notafter < io_now.tv_sec + 30 * 86400)
	    report(NULL, LOG_INFO, ~0, "peer certificate for %s will expire in %lld days", ctx->peer_addr_ascii.txt,
		   (long long) (notafter - io_now.tv_sec) / 86400);

	if (ctx->tls_peer_cert_subject.txt) {
	    char *cn = alloca(ctx->tls_peer_cert_subject.len + 1);

	    // normalize subject
	    cn[ctx->tls_peer_cert_subject.len] = 0;
	    for (size_t i = 0; i < ctx->tls_peer_cert_subject.len; i++)
		cn[i] = tolower(ctx->tls_peer_cert_subject.txt[i]);

	    // set cn
	    while (cn) {
		char *e = strchr(cn, ',');
		if (e)
		    *e = 0;
		while (isspace(*cn))
		    cn++;
		if (cn[0] == 'c' && cn[1] == 'n' && cn[2] == '=') {
		    cn += 3;
		    while (*cn && isspace(*cn))
			cn++;
		    e = cn;
		    while (*e && !isspace(*e))
			e++;
		    *e = 0;
		    str_set(&ctx->tls_peer_cn, mem_strdup(ctx->mem, cn), 0);
		    break;
		}

		if (e)
		    cn = e + 1;
		else
		    break;
	    }

	}
	if (ctx->fingerprint_matched == BISTATE_NO) {
	    // check SANs -- cycle through all DNS SANs and find the best host match

	    STACK_OF(GENERAL_NAME) * san;
	    if (cert && (san = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL))) {
		int skipped_max = 1024;
		int san_count = sk_GENERAL_NAME_num(san);
		ctx->tls_peer_cert_san = mem_alloc(ctx->mem, san_count);
		tac_host *h = NULL;
		for (int i = 0; i < san_count; i++) {
		    GENERAL_NAME *val = sk_GENERAL_NAME_value(san, i);
		    if (val->type == GEN_DNS) {
			char *t = (char *) ASN1_STRING_get0_data(val->d.dNSName);
			ctx->tls_peer_cert_san[ctx->tls_peer_cert_san_count++] = mem_strdup(ctx->mem, t);
			for (int skipped = 0; skipped < skipped_max && t; skipped++) {
			    h = lookup_host(t, ctx->realm);
			    if (h && skipped_max > skipped) {
				skipped_max = skipped;
				ctx->host = h;
				break;
			    }
			    t = strchr(t, '.');
			    if (t)
				t++;
			}
		    }
		}
		GENERAL_NAMES_free(san);
	    }
	    X509_free(cert);

	    // check for dn match:
	    if (!ctx->host)
		set_host_by_dn(ctx, (char *) ctx->tls_peer_cert_subject.txt);

	    // check for cn match:
	    if (!ctx->host)
		set_host_by_dn(ctx, ctx->tls_peer_cn.txt);
	}
    }
#ifndef OPENSSL_NO_PSK
  done:
#endif

    // fall back to IP address
    if (!ctx->host)
	ctx->host = by_address;

    if (ctx->host) {
	complete_host(ctx->host);
	if (ctx->host && (ctx->host->try_mavis == TRISTATE_YES)) {
	    ctx->mavis_tried = 0;
	    complete_host_mavis_tls(ctx);
	    return;
	}
	accept_control_final(ctx);
	return;
    }
    reject_conn(ctx, hint, "TLS ", __LINE__);
}
#endif

static void accept_control_px(int s, struct scm_data_accept_ext *sd)
{
    struct context_px *ctx = new_context_px(common_data.io, sd);
    ctx->sock = s;
    io_register(ctx->io, ctx->sock, ctx);
    io_set_cb_i(ctx->io, ctx->sock, (void *) read_px);
    io_set_cb_h(ctx->io, ctx->sock, (void *) cleanup_px);
    io_set_cb_e(ctx->io, ctx->sock, (void *) cleanup_px);
    io_set_i(ctx->io, ctx->sock);
    io_sched_add(ctx->io, ctx, (void *) try_raw, 2, 0);
}

void complete_host(tac_host *h)
{
    if (!h->complete && h->parent) {
	tac_host *hp = h->parent;
	complete_host(hp);

#define HS(A,B) if (h->A == B) h->A = hp->A
	HS(anon_enable, TRISTATE_DUNNO);
	HS(augmented_enable, TRISTATE_DUNNO);
	HS(single_connection, TRISTATE_DUNNO);
	HS(authfallback, TRISTATE_DUNNO);
	HS(cleanup_when_idle, TRISTATE_DUNNO);
	HS(authz_if_authc, TRISTATE_DUNNO);
	HS(map_pap_to_login, TRISTATE_DUNNO);
	HS(try_mavis, TRISTATE_DUNNO);
	HS(password_expiry_warning, 0);
#ifdef WITH_DNS
	HS(lookup_revmap_nas, TRISTATE_DUNNO);
	if (h->lookup_revmap_nas == TRISTATE_DUNNO) {
	    tac_realm *r = h->realm;
	    while (r && (r->default_host->lookup_revmap_nas == TRISTATE_DUNNO))
		r = r->parent;
	    if (r)
		h->lookup_revmap_nas = r->default_host->lookup_revmap_nas;
	}
	HS(lookup_revmap_nac, TRISTATE_DUNNO);
	if (h->lookup_revmap_nac == TRISTATE_DUNNO) {
	    tac_realm *r = h->realm;
	    while (r && (r->default_host->lookup_revmap_nac == TRISTATE_DUNNO))
		r = r->parent;
	    if (r)
		h->lookup_revmap_nac = r->default_host->lookup_revmap_nac;
	}
#endif
	HS(welcome_banner, NULL);
	HS(welcome_banner_fallback, NULL);
	HS(reject_banner, NULL);
	HS(authfail_banner, NULL);
	HS(motd, NULL);
	HS(key, NULL);
	HS(radius_key, NULL);
	HS(target_realm, NULL);
#ifdef WITH_SSL
#ifndef OPENSSL_NO_PSK
	HS(tls_psk_id, NULL);
	if (!h->tls_psk_key) {
	    h->tls_psk_key = hp->tls_psk_key;
	    h->tls_psk_key_len = hp->tls_psk_key_len;
	}
#endif
	HS(tls_peer_cert_validation, S_unknown);
#endif

#undef HS
#define HS(A) if(h->A < 0) h->A = hp->A
	HS(tcp_timeout);
	HS(session_timeout);
	HS(context_timeout);
	HS(dns_timeout);
	HS(authen_max_attempts);
	HS(max_rounds);
#undef HS
	h->debug |= hp->debug;
	h->bug_compatibility |= hp->bug_compatibility;

	if (h->enable) {
	    if (hp->enable) {
		for (int level = TAC_PLUS_PRIV_LVL_MIN; level < TAC_PLUS_PRIV_LVL_MAX + 1; level++)
		    if (!h->enable[level])
			h->enable[level] = hp->enable[level];
	    }
	} else
	    h->enable = hp->enable;

	if (h->user_messages) {
	    for (enum user_message_enum um = 0; um < UM_MAX; um++)
		if (!h->user_messages[um])
		    h->user_messages[um] = hp->user_messages[um];
	} else
	    h->user_messages = hp->user_messages;

	h->complete = 1;
    }
}

#ifdef WITH_SSL
static int app_verify_cb(X509_STORE_CTX *sctx, void *app_ctx)
{
    struct context *ctx = (struct context *) app_ctx;
    if (ctx->host->tls_peer_cert_validation == S_none)
	return 1;

    X509 *cert = X509_STORE_CTX_get0_cert(sctx);
    if (!cert)
	return 0;

    struct fingerprint *fp_sha1 = mem_alloc(ctx->mem, sizeof(struct fingerprint));
    fp_sha1->type = S_tls_peer_cert_sha1;
    struct fingerprint *fp_sha256 = mem_alloc(ctx->mem, sizeof(struct fingerprint));
    fp_sha256->type = S_tls_peer_cert_sha256;

    X509_digest(cert, EVP_sha1(), fp_sha1->hash, NULL);
    X509_digest(cert, EVP_sha256(), fp_sha256->hash, NULL);

    ctx->fingerprint = fp_sha1;
    fp_sha1->next = fp_sha256;

    if ((ctx->host->tls_peer_cert_validation != S_hash) &&	//
	(X509_check_purpose(cert, X509_PURPOSE_SSL_CLIENT, 0) == 1) &&	//
	(X509_verify_cert(sctx) == 1))
	return 1;

    if (ctx->host->tls_peer_cert_validation != S_cert) {
	if (ctx->host->mem) {	// dynamic host, compare cert fingerprint to the one supplied by the MAVIS
	    for (struct fingerprint * fp = ctx->host->fingerprint; fp; fp = fp->next)
		if (!compare_fingerprint(fp, ctx->fingerprint)) {
		    ctx->fingerprint_matched = BISTATE_YES;
		    return 1;
		}
	} else {		// static host, lookup fingerprint
	    struct fingerprint *fp = lookup_fingerprint(ctx);
	    if (fp) {
		ctx->host = fp->host;
		ctx->fingerprint_matched = BISTATE_YES;
		return 1;
	    }
	}
    }

    ctx->hint = "Certificate verification";
    return 0;			// 0: failure, 1: success
}

static int alpn_cb(SSL *s __attribute__((unused)), const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg)
{
    struct context *ctx = (struct context *) arg;
#define ALPN_RADIUS_1_1 "\012radius/1.1"
    if (SSL_select_next_proto((unsigned char **) out, outlen, (const unsigned char *) ALPN_RADIUS_1_1, sizeof(ALPN_RADIUS_1_1) - 1, in, inlen) ==
	OPENSSL_NPN_NEGOTIATED)
	ctx->radius_1_1 = BISTATE_YES;

    if (ctx->realm->alpn_vec && ctx->realm->alpn_vec_len > 1
	&& SSL_select_next_proto((unsigned char **) out, outlen, ctx->realm->alpn_vec, ctx->realm->alpn_vec_len, in, inlen) != OPENSSL_NPN_NEGOTIATED) {
	ctx->hint = "ALPN verification";
	ctx->alpn_passed = TRISTATE_NO;
	return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    ctx->alpn_passed = TRISTATE_YES;

    return SSL_TLSEXT_ERR_OK;
}

static int sni_cb(SSL *s, int *al __attribute__((unused)), void *arg)
{
    struct context *ctx = (struct context *) arg;
    const char *servername = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);
    tac_realm *r = servername ? lookup_sni(servername, strlen(servername), ctx->realm, &ctx->tls_sni.txt, &ctx->tls_sni.len) : NULL;

    if (!r)
	goto fatal;

    if (r != ctx->realm) {
	ctx->realm = r;
	while (r && !r->tls)
	    r = r->parent;
	if (!r || !r->tls || !SSL_set_SSL_CTX(s, r->tls))
	    goto fatal;
    }

    ctx->sni_passed = BISTATE_YES;

    return SSL_TLSEXT_ERR_OK;

  fatal:
    ctx->hint = "SNI verification";
    *al = SSL_AD_UNRECOGNIZED_NAME;
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

static int SSLKEYLOGFILE = -1;
static void keylog_cb(const SSL *ssl __attribute__((unused)), const char *line)
{
    if (SSLKEYLOGFILE > -1) {
	struct flock flock = {.l_type = F_WRLCK,.l_whence = SEEK_SET };
	fcntl(SSLKEYLOGFILE, F_SETLK, &flock);

	lseek(SSLKEYLOGFILE, 0, SEEK_END);
	write(SSLKEYLOGFILE, line, strlen(line));
	write(SSLKEYLOGFILE, line, strlen(line));

	struct flock funlock = {.l_type = F_UNLCK,.l_whence = SEEK_SET };
	fcntl(SSLKEYLOGFILE, F_SETLK, &funlock);
    }
}
#endif

static tac_realm *set_sd_realm(int s __attribute__((unused)), struct scm_data_accept_ext *sd)
{
#ifdef VRF_BINDTODEVICE
    if (s > 0) {
	// Reminder to myself:
	//      sysctl -w net.ipv4.tcp_l3mdev_accept=1
	// is the "vrf-also" variant in case the spawnd configuration wasn't adjusted to use VRFs.
	socklen_t opt_len = sizeof(sd->vrf);
	*sd->vrf = 0;
	if (getsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, (u_char *) sd->vrf, &opt_len))
	    report(NULL, LOG_ERR, ~0, "getsockopt(SO_BINDTODEVICE) failed at %s:%d: %s", __FILE__, __LINE__, strerror(errno));
	else if (opt_len > 0) {
	    if (!sd->vrf[opt_len - 1])
		opt_len--;
	    sd->vrf_len = opt_len;
	}
    }
#endif
#ifdef VRF_RTABLE
    if (s > 0) {
	unsigned int opt;
	socklen_t optlen = sizeof(opt);
	if (getsockopt(s, SOL_SOCKET, SO_RTABLE, &opt, &optlen))
	    report(NULL, LOG_ERR, ~0, "getsockopt(SO_RTABLE) failed at %s:%d: %s", __FILE__, __LINE__, strerror(errno));
	else
	    sd->vrf_len = snprintf(sd->vrf, sizeof(sd->vrf), "%u", opt);
    }
#endif

    tac_realm *r = config.default_realm;

    if (*sd->sd.realm)
	r = lookup_realm(sd->sd.realm, r);
    if (!r)
	r = config.default_realm;

    // Still at the default realm? Try the VRF name:
    if (sd->vrf_len && (r == config.default_realm))
	r = lookup_realm(sd->vrf, r);

    if (!r)
	r = config.default_realm;

    sd->realm = r;
    return r;
}

static void complete_host_mavis(struct context *);

static void set_ctx_info(struct context *ctx, struct scm_data_accept_ext *sd_ext)
{
    sockaddr_union me = { 0 };
    socklen_t me_len = (socklen_t) sizeof(me);
    if (!getsockname(ctx->sock, &me.sa, &me_len)) {
	char buf[256];
	su_convert(&me, AF_INET);
	snprintf(buf, 10, "%u", su_get_port(&me));
	str_set(&ctx->server_port_ascii, mem_strdup(ctx->mem, buf), 0);
	if (su_ntoa(&me, buf, sizeof(buf)))
	    str_set(&ctx->server_addr_ascii, mem_strdup(ctx->mem, buf), 0);
    }
    if (sd_ext->vrf_len)
	str_set(&ctx->vrf, mem_strndup(ctx->mem, (u_char *) sd_ext->vrf, sd_ext->vrf_len), 0);
}

static void accept_control_common(int s, struct scm_data_accept_ext *sd_ext, sockaddr_union *device_addr, u_char *inject_buf, size_t inject_len)
{
    fcntl(s, F_SETFD, FD_CLOEXEC);
    fcntl(s, F_SETFL, O_NONBLOCK);

    sockaddr_union peer = { 0 };
    socklen_t peer_len = (socklen_t) sizeof(peer);

    if (getpeername(s, &peer.sa, &peer_len)) {
	// error path
	report(NULL, LOG_DEBUG, DEBUG_PACKET_FLAG, "getpeername: %s", strerror(errno));
	io_close(common_data.io, s);

	users_dec();

	if (ctx_spawnd && die_when_idle)
	    cleanup_spawnd(ctx_spawnd, -1);
	return;
    }

    tac_realm *r = set_sd_realm(s, sd_ext);
    struct context *ctx = new_context(common_data.io, r);

    char *proxy_addr_ascii = NULL;
    size_t proxy_addr_ascii_len = 0;
    char buf[256];
    if (device_addr) {		// proxied
	proxy_addr_ascii = mem_strdup(ctx->mem, su_ntoa(&peer, buf, sizeof(buf)) ? buf : "<unknown>");
	proxy_addr_ascii_len = strlen(proxy_addr_ascii);
    } else			// not proxied
	device_addr = &peer;

    su_convert(device_addr, AF_INET);
    su_ptoh(device_addr, &ctx->device_addr);

    tac_host *h = NULL;
    radixtree_t *rxt = lookup_hosttree(r);
    if (rxt)
	h = radix_lookup(rxt, &ctx->device_addr, NULL);

    if (h) {
	complete_host(h);

	if (h->target_realm && r != h->target_realm) {
	    r = h->target_realm;
	    rxt = lookup_hosttree(r);
	    if (rxt) {
		h = radix_lookup(rxt, &ctx->device_addr, NULL);
		if (h)
		    complete_host(h);
	    }
	}
    }
    ctx->rad_acct = (sd_ext->sd.flags & SCM_FLAG_RADACCT) ? BISTATE_YES : BISTATE_NO;
    ctx->sock = s;
    io_register(ctx->io, ctx->sock, ctx);

    context_lru_append(ctx);
    ctx->tls_versions = sd_ext->sd.tls_versions;
    ctx->use_tls = (sd_ext->sd.tls_versions && sd_ext->sd.type == SCM_ACCEPT) ? BISTATE_YES : BISTATE_NO;
    ctx->use_dtls = (sd_ext->sd.tls_versions && sd_ext->sd.type == SCM_UDPDATA) ? BISTATE_YES : BISTATE_NO;
    if (inject_buf) {
	ctx->udp = BISTATE_YES;
	ctx->inject_buf = mem_copy(ctx->mem, inject_buf, inject_len);
	ctx->inject_len = inject_len;
    }

    if (ctx->use_tls == BISTATE_NO) {
	if (h) {
	    if (!h->key)
		ctx->hint = "no encryption key found";
	} else
	    ctx->hint = "host unknown";
    }

    str_set(&ctx->peer_addr_ascii, mem_strdup(ctx->mem, su_ntoa(&peer, buf, sizeof(buf)) ? buf : "<unknown>"), 0);
    snprintf(buf, sizeof(buf), "%u", su_get_port(&peer));
    str_set(&ctx->peer_port_ascii, mem_strdup(ctx->mem, buf), 0);

    str_set(&ctx->proxy_addr_ascii, proxy_addr_ascii, proxy_addr_ascii_len);

    if (device_addr == &peer) {
	ctx->device_addr_ascii = ctx->peer_addr_ascii;
	ctx->device_port_ascii = ctx->peer_port_ascii;
    } else {
	str_set(&ctx->device_addr_ascii, mem_strdup(ctx->mem, su_ntoa(device_addr, buf, sizeof(buf)) ? buf : "<unknown>"), 0);
	snprintf(buf, sizeof(buf), "%u", (short) su_get_port(device_addr));
	str_set(&ctx->device_port_ascii, mem_strdup(ctx->mem, buf), 0);
    }
    ctx->host = h;

    set_ctx_info(ctx, sd_ext);

    complete_host_mavis(ctx);
}

static int query_mavis_host(struct context *ctx, void (*f)(struct context *))
{
    if(!ctx->host || ctx->host->try_mavis != TRISTATE_YES)
	return 0;
    if (!ctx->mavis_tried) {
	ctx->mavis_tried = 1;
	mavis_ctx_lookup(ctx, f, AV_V_TACTYPE_HOST);
	return -1;
    }
    return 0;
}

static void complete_host_mavis(struct context *ctx)
{
    if (query_mavis_host(ctx, complete_host_mavis))
	return;

    if (ctx->mavis_result == S_deny) {
	reject_conn(ctx, ctx->hint, "by MAVIS backend", __LINE__);
	return;
    }

    if (ctx->host)
	ctx->key = ctx->host->key;

    io_set_cb_i(ctx->io, ctx->sock, (void *) accept_control_check_tls);
    io_set_cb_o(ctx->io, ctx->sock, (void *) accept_control_check_tls);
    io_set_cb_h(ctx->io, ctx->sock, (void *) cleanup);
    io_set_cb_e(ctx->io, ctx->sock, (void *) cleanup);
    io_sched_add(ctx->io, ctx, (void *) periodics_ctx, 60, 0);
    io_set_i(ctx->io, ctx->sock);
    if (ctx->udp)
	accept_control_check_tls(ctx, ctx->sock);
}

ssize_t recv_inject(struct context *ctx, void *buf, size_t len, int flags)
{
    if (ctx->inject_buf && ctx->inject_len > ctx->inject_off) {
	if (ctx->inject_len - ctx->inject_off < len)
	    len = ctx->inject_len - ctx->inject_off;
	memcpy(buf, ctx->inject_buf + ctx->inject_off, len);
	if (!(flags & MSG_PEEK))
	    ctx->inject_off += len;
	if (ctx->inject_off == ctx->inject_len)
	    mem_free(ctx->mem, &ctx->inject_buf);
	return len;
    }
    ssize_t res = recv(ctx->sock, buf, len, flags);
    return (!res && len) ? -1 : res;
}

#ifdef WITH_SSL
static int dtls_ver_ok(u_int ver, u_char v)
{
    for (; ver; ver >>= 8)
	if ((ver & 0xff) == v)
	    return -1;
    return 0;
}
#endif

static void accept_control_check_tls(struct context *ctx, int cur __attribute__((unused)))
{
#ifdef WITH_SSL
    u_char tmp[6];
    if (recv_inject(ctx, tmp, sizeof(tmp), MSG_PEEK) == (ssize_t) sizeof(tmp)) {
	if (ctx->udp && tmp[0] == 0x17 && tmp[1] == 0xfe && dtls_ver_ok(ctx->tls_versions, tmp[2])) {
	    // DTLS Application Data, but we haven't seen the handshake, possibly due to a daemon
	    // restart. Just return some junk data back , the peer is likely to retry with a new handshake.
	    char junk[128] = { 0 };
	    write(ctx->sock, junk, sizeof(junk));
	    cleanup(ctx, ctx->sock);
	    return;
	}
	if (ctx->realm->tls_autodetect == TRISTATE_YES && tmp[0] == 0x16) {
	    if (ctx->udp)
		ctx->use_dtls = (tmp[1] == 0xfe && dtls_ver_ok(ctx->tls_versions, tmp[2])) ? BISTATE_YES : BISTATE_NO;
	    else
		ctx->use_tls = (tmp[1] == 0x03 && tmp[2] == 0x01 && tmp[5] == 1) ? BISTATE_YES : BISTATE_NO;
	}
    }
    if (ctx->host && (ctx->use_tls || ctx->use_dtls)) {
	if ((ctx->use_tls && !ctx->realm->tls && !ctx->realm->use_tls_psk) || (ctx->use_dtls && !ctx->realm->dtls && !ctx->realm->use_tls_psk)) {
	    report(NULL, LOG_ERR, ~0, "%s but realm %s isn't configured suitably",
		   (ctx->realm->tls_autodetect == TRISTATE_YES) ? "TLS detected" : "spawnd set TLS flag", ctx->realm->name.txt);
	    cleanup(ctx, ctx->sock);
	    return;
	}
	io_set_cb_i(ctx->io, ctx->sock, (void *) accept_control_tls);
	io_set_cb_o(ctx->io, ctx->sock, (void *) accept_control_tls);
	io_set_cb_h(ctx->io, ctx->sock, (void *) cleanup);
	io_set_cb_e(ctx->io, ctx->sock, (void *) cleanup);
	io_sched_add(ctx->io, ctx, (void *) periodics_ctx, 60, 0);

	SSL_CTX_set_cert_verify_callback(ctx->realm->tls, app_verify_cb, ctx);
	SSL_CTX_set_alpn_select_cb(ctx->realm->tls, alpn_cb, ctx);

	if (ctx->realm->tls_sni_required == TRISTATE_YES) {
	    SSL_CTX_set_tlsext_servername_callback(ctx->realm->tls, sni_cb);
	    SSL_CTX_set_tlsext_servername_arg(ctx->realm->tls, ctx);
	} else
	    ctx->sni_passed = BISTATE_YES;

	char *sslkeylogfile = getenv("SSLKEYLOGFILE");
	if (sslkeylogfile) {
	    SSLKEYLOGFILE = open(sslkeylogfile, O_CREAT | O_APPEND, 0644);
	    if (SSLKEYLOGFILE > -1)
		SSL_CTX_set_keylog_callback(ctx->realm->tls, keylog_cb);
	}

	ctx->tls = SSL_new(ctx->use_tls ? ctx->realm->tls : (ctx->use_dtls ? ctx->realm->dtls : NULL));

	if (ctx->tls) {
	    u_int versions = ctx->tls_versions;
	    int ver = 0;
	    if (ctx->udp) {
#ifdef DTLS1_3_VERSION
		ver = DTLS1_3_VERSION & 0xff;
#else
		ver = DTLS1_2_VERSION & 0xff;
#endif
		while (versions) {
		    int tmp = versions & 0xFF;
		    if (ver && tmp > ver)
			ver = tmp;
		    versions >>= 8;
		}
		ver |= 0xFE00;
	    } else {
		ver = TLS1_3_VERSION & 0xff;
		while (versions) {
		    int tmp = versions & 0xFF;
		    if (ver && tmp < ver)
			ver = tmp;
		    versions >>= 8;
		}
		ver |= 0x0300;
	    }
	    SSL_set_min_proto_version(ctx->tls, ver);
	    SSL_set_fd(ctx->tls, ctx->sock);
	    SSL_set_session_id_context(ctx->tls, (const unsigned char *) &ctx, sizeof(ctx));

	    if (ctx->udp) {
		//ctx->rbio = BIO_new(BIO_s_dgram_mem());
		ctx->rbio = BIO_new(BIO_s_mem());
		SSL_set0_rbio(ctx->tls, ctx->rbio);
		BIO_write(ctx->rbio, ctx->inject_buf, ctx->inject_len);
		mem_free(ctx->mem, &ctx->inject_buf);
	    }
	}
	accept_control_tls(ctx, ctx->sock);
	return;
    }
#endif
    if (!ctx->host)
	reject_conn(ctx, ctx->hint, "", __LINE__);
    else
	accept_control_final(ctx);
}

static void accept_control_final(struct context *ctx)
{
    static int count = 0;
    tac_session session = {.ctx = ctx };

    if (ctx->proxy_addr_ascii.txt) {
	if (!(common_data.debug & DEBUG_TACTRACE_FLAG))
	    report(&session, LOG_DEBUG, DEBUG_PACKET_FLAG, "proxied connection request from %s for %s (realm: %s%s%s)", ctx->proxy_addr_ascii.txt,
		   ctx->peer_addr_ascii.txt, ctx->realm->name.txt, ctx->vrf.txt ? ", vrf: " : "", ctx->vrf.txt ? ctx->vrf.txt : "");
    } else
	report(&session, LOG_DEBUG, DEBUG_PACKET_FLAG, "connection request from %s (realm: %s%s%s)", ctx->peer_addr_ascii.txt, ctx->realm->name.txt,
	       ctx->vrf.txt ? ", vrf: " : "", ctx->vrf.txt ? ctx->vrf.txt : "");

    get_revmap_nas(&session);

    io_set_cb_i(ctx->io, ctx->sock, (void *) tac_read);
    io_set_cb_o(ctx->io, ctx->sock, (void *) tac_write);
    io_set_cb_h(ctx->io, ctx->sock, (void *) cleanup);
    io_set_cb_e(ctx->io, ctx->sock, (void *) cleanup);
    io_set_i(ctx->io, ctx->sock);
    io_sched_add(ctx->io, ctx, (void *) periodics_ctx, 60, 0);
    if (config.retire && (++count == config.retire) && !common_data.singleprocess) {
	report(&session, LOG_INFO, ~0, "Retire limit reached. Told parent about this.");
	if (ctx_spawnd) {
	    struct scm_data d = {.type = SCM_DYING };
	    common_data.scm_send_msg(ctx_spawnd->sock, &d, -1);
	}
    }
    STATICSTR(start, "CONN-START");
    ctx->msgid = &msgid_start;
    ctx->acct_type = &conn_start;
    log_exec(NULL, ctx, S_connection, io_now.tv_sec);
    ctx->msgid = NULL;
    tac_read(ctx, ctx->sock);
}

static void accept_control(struct context *ctx, int cur)
{
    int s;

    union {
	struct scm_data_accept sd;
	struct scm_data_udp sd_udp;
	u_char buf[1024];	// radius packets are usually < 100
    } u;

    if (common_data.scm_recv_msg(cur, &u.sd, sizeof(u), &s)) {
	cleanup_spawnd(ctx, cur);
	return;
    }
    struct scm_data_accept_ext sd_ext = { 0 };

    switch (u.sd.type) {
    case SCM_MAY_DIE:
	cleanup_spawnd(ctx, cur);
	return;
    case SCM_UDPDATA:
	if (config.rad_dict) {
	    rad_pak_hdr *hdr = (rad_pak_hdr *) (&u.sd_udp.data);
	    if (u.sd_udp.data_len != ntohs(hdr->length))
		return;
	    memcpy(&sd_ext.sd, &u.sd_udp, sizeof(struct scm_data_udp));
	    users_inc();
	    set_sd_realm(cur, &sd_ext);
	    accept_control_common(s, &sd_ext, NULL, u.sd_udp.data, u.sd_udp.data_len);
	    return;
	}
	users_inc();
	users_dec();
	return;
    case SCM_ACCEPT:
	memcpy(&sd_ext.sd, &u.sd, sizeof(struct scm_data_accept));
	users_inc();
	int one = 1;
	setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char *) &one, (socklen_t) sizeof(one));
	setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *) &one, (socklen_t) sizeof(one));
	set_sd_realm(cur, &sd_ext);
	if ((sd_ext.sd.flags & SCM_FLAG_HAPROXY) || (sd_ext.realm->haproxy_autodetect == TRISTATE_YES))
	    accept_control_px(s, &sd_ext);
	else
	    accept_control_raw(s, &sd_ext);
	return;
    default:
	if (s > -1)
	    close(s);
    }
}
