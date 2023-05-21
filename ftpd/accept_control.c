/*
 * accept_control.c
 * (C)1997-2011 by Marc Huber <Marc.Huber@web.de>
 *
 * $Id$
 *
 */

#include "headers.h"

#ifdef WITH_SCTP
#include <netinet/sctp.h>
#endif

#ifdef WITH_SSL
#include "misc/ssl_init.h"
#endif

static const char rcsid[] __attribute__((used)) = "$Id$";

void print_banner(struct context *ctx)
{
    io_set_cb_o(ctx->io, ctx->cfn, (void *) control2socket);

    if (ctx->banner_bye) {
	io_clr_cb_i(ctx->io, ctx->cfn);
	file2control(ctx, "421", ctx->banner);
	io_clr_i(ctx->io, ctx->cfn);
    } else {
	io_set_cb_i(ctx->io, ctx->cfn, (void *) readcmd);
	file2control(ctx, "220", ctx->banner);
	replyf(ctx, "220 %s\r\n", cook(ctx, ctx->greeting, NULL, NULL, 0));
	io_set_i(ctx->io, ctx->cfn);
    }
}

#ifdef WITH_DNS
static void set_reverse(struct context *ctx, char *hostname, int ttl __attribute__((unused)))
{
    if (hostname)
	strset(&ctx->reverse, hostname);
}
#endif				/* WITH_DNS */



void accept_control_raw(int s, struct scm_data_accept *sd)
{
    static u_long id = 0;
    socklen_t sinlen = (socklen_t) sizeof(sockaddr_union);
    struct context *ctx = new_context(common_data.io);

    DebugIn(DEBUG_NET);

    fcntl(s, F_SETFL, O_NONBLOCK);
    fcntl(s, F_SETFD, FD_CLOEXEC);
    ctx->cfn = s;
    ctx->state = ST_conn;
    ctx->id = id++;
    ctx->is_client = 1;
    common_data.users_cur++;
    io_register(ctx->io, s, ctx);
    io_set_cb_e(ctx->io, s, (void *) cleanup_control);
    io_set_cb_h(ctx->io, s, (void *) cleanup_control);

    if (id_max && id == id_max && !common_data.singleprocess) {
	struct scm_data d;
	d.type = SCM_DYING;
	common_data.scm_send_msg(0, &d, -1);
	die_when_idle = -1;
	logmsg("Retire limit reached. Told parent about this.");
    }
#ifdef WITH_SCTP
    if (sd->protocol == IPPROTO_SCTP && sd->socktype == SOCK_SEQPACKET) {
	ctx->cfn = sctp_peeloff(s, 1);	// FIXME ...
	if (ctx->cfn < 0) {
	    logerr("sctp_peeloff");
	    cleanup(ctx, s);
	    Debug((DEBUG_NET, "- %s: getpeername failure\n", __func__));
	    return;
	}
	ctx->sctp_fn = s;
	s = ctx->cfn;
#if 1
	/*
	 * 1:n ftp associations aren't standardized in any way.
	 */
	close(ctx->sctp_fn);
	ctx->sctp_fn = -1;
#endif
    }
#endif

    if (getpeername(s, &ctx->sa_c_remote.sa, &sinlen)) {
	logerr("getpeername (%s:%d)", __FILE__, __LINE__);
	cleanup(ctx, s);
	Debug((DEBUG_NET, "- %s: getpeername failure\n", __func__));
	return;
    }

    ctx->sa_d_remote = ctx->sa_c_remote;

    sinlen = (socklen_t) sizeof(sockaddr_union);
    if (getsockname(s, &ctx->sa_c_local.sa, &sinlen)) {
	logerr("getsockname (%s:%d)", __FILE__, __LINE__);
	cleanup(ctx, s);
	Debug((DEBUG_NET, "- %s: getsockname failure\n", __func__));
	return;
    }
#ifdef WITH_DNS
    if (idc)
	io_dns_add(idc, &ctx->sa_c_remote, (void *) set_reverse, ctx);
#endif				/* WITH_DNS */

    su_ptoh(&ctx->sa_c_remote, &ctx->in6_remote);
    su_ptoh(&ctx->sa_c_local, &ctx->in6_local);

    acl_calc(ctx);

    if (ctx->ident_query)
	ident_connect_out(ctx, s);

    if (!ctx->accept && !ctx->banner_bye) {
	cleanup(ctx, s);
	DebugOut(DEBUG_NET);
	return;
    }

    ctx->protocol = sd->protocol;

    set_proctitle(die_when_idle ? ACCEPT_NEVER : ACCEPT_YES);

#ifdef WITH_SSL
    if (sd->use_tls) {
	ctx->use_tls_c = ctx->use_tls_d = 1;
	if (ssl_auth)
	    ssl_set_verify(ssl_ctx, ctx);
	ctx->ssl_c = SSL_new(ssl_ctx);
	SSL_set_fd(ctx->ssl_c, s);
	do_accept_c(ctx, s);
    } else {
	ctx->use_tls_d = 0;
	print_banner(ctx);
    }
#else				/* WITH_SSL */
    print_banner(ctx);
#endif				/* WITH_SSL */

    ftp_log(ctx, LOG_EVENT, "login");
    ctx->login_logged = 1;

    DebugOut(DEBUG_NET);
}

void accept_control(struct context *ctx, int cur __attribute__((unused)))
{
    int s = -1;
    struct scm_data_accept sd;

    DebugIn(DEBUG_NET);

    if (common_data.scm_recv_msg(ctx->cfn, &sd, sizeof(sd), &s)) {
	logerr("scm_recv_msg");
	Debug((DEBUG_NET, "- %s: scm_recv_msg failure\n", __func__));
	cleanup(ctx, ctx->cfn);
	die_when_idle = -1;
	return;
    }

    switch (sd.type) {
    case SCM_MAY_DIE:
	if (common_data.users_cur == 0) {
	    Debug((DEBUG_PROC, "exiting -- process out of use\n"));
	    mavis_drop(mcx);
	    logmsg("Terminating, no longer needed.");
	    exit(EX_OK);
	}
	die_when_idle = -1;
	break;
    case SCM_ACCEPT:
	accept_control_raw(s, &sd);
	break;
    default:
	if (s > -1)
	    close(s);
    }

    DebugOut(DEBUG_NET);
}
