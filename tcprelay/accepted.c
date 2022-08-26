/*
 * accepted.c
 * (C)1999-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

#ifdef WITH_TLS
static void do_accept_c(struct context *ctx, int cur)
{
    int r = 0;

    DebugIn(DEBUG_NET);

    io_clr_i(ctx->io, cur);
    io_clr_o(ctx->io, cur);

    switch (tls_handshake(ctx->ssl)) {
    case TLS_WANT_POLLIN:
	io_set_i(ctx->io, cur);
	r++;
	break;
    case TLS_WANT_POLLOUT:
	io_set_o(ctx->io, cur);
	r++;
	break;
    case -1:
	cleanup(ctx, cur);
	break;
    case 0:
	io_set_cb_i(ctx->io, cur, (void *) socket2buffer);
	io_set_cb_o(ctx->io, cur, (void *) buffer2socket);
	io_set_cb_e(ctx->io, cur, (void *) cleanup_error);
	io_set_cb_h(ctx->io, cur, (void *) cleanup_error);
	connect_out(ctx, cur);
	break;
    }
    DebugOut(DEBUG_NET);
}
#else
#ifdef WITH_SSL
static void do_accept_c(struct context *ctx, int cur)
{
    int r;

    DebugIn(DEBUG_NET);

    io_clr_i(ctx->io, cur);
    io_clr_o(ctx->io, cur);

    switch (SSL_accept(ctx->ssl)) {
    default:			/* not completed */
	r = 0;
	io_set_cb_i(ctx->io, cur, (void *) do_accept_c);
	io_set_cb_o(ctx->io, cur, (void *) do_accept_c);
	io_set_cb_e(ctx->io, cur, (void *) cleanup_error);
	io_set_cb_h(ctx->io, cur, (void *) cleanup_error);
	if (SSL_want_read(ctx->ssl)) {
	    io_set_i(ctx->io, cur);
	    r++;
	}
	if (SSL_want_write(ctx->ssl)) {
	    io_set_o(ctx->io, cur);
	    r++;
	}
	if (!r) {
	    logmsg("SSL_accept(%s:%d): %s", __FILE__, __LINE__, ERR_error_string(ERR_get_error(), NULL));
	    cleanup(ctx, cur);
	}
	break;
    case 0:
	cleanup(ctx, cur);
	break;
    case 1:
	io_set_cb_i(ctx->io, cur, (void *) socket2buffer);
	io_set_cb_o(ctx->io, cur, (void *) buffer2socket);
	io_set_cb_e(ctx->io, cur, (void *) cleanup_error);
	io_set_cb_h(ctx->io, cur, (void *) cleanup_error);
	connect_out(ctx, cur);
	break;
    }
    DebugOut(DEBUG_NET);
}
#endif				/* WITH_SSL */
#endif				/* WITH_TLS */

void accepted_raw(int s, struct scm_data_accept *sd __attribute__((unused)))
{
    static u_long id = 0;
    int bufsize = BUFSIZE + 512;
    int one = 1;
    struct context *ctx;

    DebugIn(DEBUG_NET);

    fcntl(s, F_SETFL, O_NONBLOCK);

    setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char *) &one, (socklen_t) sizeof(one));

    ctx = new_context(common_data.io);
    io_register(ctx->io, s, ctx);
    ctx->ifn = s;
    ctx->is_client = 1;
    io_set_cb_i(ctx->io, s, (void *) socket2buffer);
    io_set_cb_o(ctx->io, s, (void *) buffer2socket);
    io_set_cb_e(ctx->io, s, (void *) cleanup_error);
    io_set_cb_h(ctx->io, s, (void *) cleanup_error);
    common_data.users_cur++;

    if (id_max && ++id == id_max && !common_data.singleprocess) {
	struct scm_data d;
	d.type = SCM_DYING;
	common_data.scm_send_msg(0, &d, -1);
	die_when_idle = -1;
	logmsg("Retire limit reached. Told parent about this.");
    }
    if (conntimeout)
	io_sched_add(ctx->io, ctx, (void *) cleanup, conntimeout, 0);

    fcntl(s, F_SETFL, O_NONBLOCK);

    setsockopt(s, SOL_SOCKET, SO_SNDBUF, (char *) &bufsize, (socklen_t) sizeof(bufsize));
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, (char *) &bufsize, (socklen_t) sizeof(bufsize));

    set_proctitle(die_when_idle ? ACCEPT_NEVER : ACCEPT_YES);

#ifdef WITH_TLS
    if (sd->use_tls) {
	tls_accept_socket(ssl_ctx, &ctx->ssl, s);
	io_set_cb_i(ctx->io, s, (void *) do_accept_c);
	io_set_cb_o(ctx->io, s, (void *) do_accept_c);
	io_set_cb_e(ctx->io, s, (void *) cleanup_error);
	io_set_cb_h(ctx->io, s, (void *) cleanup_error);
	do_accept_c(ctx, s);
    } else {
	ctx->ssl = NULL;
	connect_out(ctx, s);
    }
#else
#ifdef WITH_SSL
    if (sd->use_tls) {
	ctx->ssl = SSL_new(ssl_ctx);
	SSL_set_fd(ctx->ssl, s);
	do_accept_c(ctx, s);
    } else {
	ctx->ssl = NULL;
	connect_out(ctx, s);
    }
#else
    connect_out(ctx, s);
#endif				/* WITH_SSL */
#endif				/* WITH_SSL */

    DebugOut(DEBUG_NET);
}

void accepted(struct context *ctx, int cur)
{
    int s;
    struct scm_data_accept sd;

    DebugIn(DEBUG_NET);

    if (common_data.scm_recv_msg(cur, &sd, sizeof(sd), &s)) {
	logerr("scm_recv_msg");
	Debug((DEBUG_NET, "- %s: scm_recv_msg failure\n", __func__));
	cleanup(ctx, cur);
	die_when_idle = -1;
	return;
    }
    switch (sd.type) {
    case SCM_MAY_DIE:{
	    if (common_data.users_cur == 0) {
		Debug((DEBUG_PROC, "exiting -- process out of use\n"));
		logmsg("Terminating, no longer needed.");
		exit(EX_OK);
	    }
	    die_when_idle = -1;
	    break;
    case SCM_ACCEPT:
	    accepted_raw(s, &sd);
	    break;
    default:
	    if (s > -1)
		close(s);
	}
    }

    DebugOut(DEBUG_NET);
}
