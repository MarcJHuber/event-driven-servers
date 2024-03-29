/*
 * accept_data.c
 *
 * (C)1997-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

#ifdef WITH_SSL
void sslify_d(struct context *, int);
#endif

int is_connected(int sock)
{
    sockaddr_union su;
    socklen_t salen = (socklen_t) sizeof(su);
    return !getpeername(sock, &su.sa, &salen);
}

static void connect_data_failed(struct context *ctx, int cur __attribute__((unused)))
{
    reply(ctx, MSG_431_Opening_datacon_failed);
    ctx->dbuf = buffer_free_all(ctx->dbuf);
    cleanup_data(ctx, cur);
}

void connect_data(struct context *ctx, int cur __attribute__((unused)))
{
    size_t bs = bufsize + 512;

    DebugIn(DEBUG_NET);

    io_set_cb_e(ctx->io, ctx->dfn, (void *) cleanup_data);

    io_sched_del(ctx->io, ctx, (void *) cleanup_data);
    fcntl(ctx->dfn, F_SETFL, O_NONBLOCK);

    setsockopt(ctx->dfn, SOL_SOCKET, ctx->outgoing_data ? SO_SNDBUF : SO_RCVBUF, (char *) &bs, (socklen_t) sizeof(bs));

#ifdef WITH_SSL
    if (ctx->use_tls_d && ctx->ssl_c) {
	Debug((DEBUG_NET, "sslify_d\n"));
	sslify_d(ctx, ctx->dfn);
    } else
#endif				/* WITH_SSL */
	do_connect_d(ctx, ctx->dfn);

    ctx->count_total++;
    DebugOut(DEBUG_NET);
}

void accept_data(struct context *ctx, int cur __attribute__((unused)))
{
    int s, failure;
    sockaddr_union su = { 0 };
    socklen_t sulen = (socklen_t) sizeof(su);

    DebugIn(DEBUG_NET);

    io_sched_del(ctx->io, ctx, (void *) cleanup_data);

    do {
	failure = 0;

	if (0 > (s = accept(ctx->dfn, &su.sa, &sulen))) {
	    logerr("accept (%s:%d)", __FILE__, __LINE__);
	    cleanup_data(ctx, ctx->dfn);
	    Debug((DEBUG_NET, "- %s: FAILURE accept < 0\n", __func__));
	    return;
	}

	if (ctx->estp_valid && !su_equal(&su, &ctx->sa_d_estp)) {
	    close(s);
	    Debug((DEBUG_NET, "ESTP address mismatch\n"));
	    failure = -1;
	} else if (!ctx->estp && !ctx->address_mismatch && !su_equal_addr(&su, &ctx->sa_c_remote)) {
	    close(s);
	    Debug((DEBUG_NET, "address mismatch\n"));
	    failure = -1;
	}

	if (failure) {
	    char buf[160];
	    logmsg("hijacking attempt from %s", rfc2428_str(&su, buf, sizeof(buf)));
	}

    }
    while (failure);

    io_register(ctx->io, s, ctx);
    io_clone(ctx->io, s, ctx->dfn);
    io_close(ctx->io, ctx->dfn);
    ctx->dfn = s;

    connect_data(ctx, ctx->dfn);

    DebugOut(DEBUG_NET);
}

void do_connect_d(struct context *ctx, int cur __attribute__((unused)))
{
    DebugIn(DEBUG_NET);

    io_clr_o(ctx->io, ctx->dfn);

    if (ctx->estp) {
	io_set_cb_o(ctx->io, ctx->dfn, (void *) buffer2socket);
	io_set_cb_i(ctx->io, ctx->dfn, (void *) socket2buffer);
    } else if (ctx->outgoing_data) {
	if ((ctx->conversion != CONV_MD5 && ctx->conversion != CONV_CRC) || ctx->buffer_filled)
	    io_set_o(ctx->io, ctx->dfn);
	io_set_cb_o(ctx->io, ctx->dfn, (void *) buffer2socket);
	io_clr_cb_i(ctx->io, ctx->dfn);
    } else {
	io_set_i(ctx->io, ctx->dfn);
	io_set_cb_i(ctx->io, ctx->dfn, (void *) socket2buffer);
	io_clr_cb_o(ctx->io, ctx->dfn);
    }

    DebugOut(DEBUG_NET);
}

void connect_port(struct context *ctx)
{
    int s;
    sockaddr_union su;

    DebugIn(DEBUG_COMMAND);

    /* set data port to control connection port - 1 */
    su = ctx->sa_c_local;
    su_set_port(&su, su_get_port(&su) - 1);

    /*
     * Change remote address to local address family, if needed. This
     * becomes necessary if and only if we're running the dual mode
     * IPv4/v6 API and the client did send us a PORT command.
     */

    if (su_convert(&ctx->sa_d_remote, su.sa.sa_family)) {
	logmsg("af mismatch (%s:%d)", __FILE__, __LINE__);
	Debug((DEBUG_COMMAND, "- %s: su_convert #A\n", __func__));
	return;
    }

    /*
     * Solaris weirdness: Binding to a privileged port requires the
     * socket to be created by root.
     */
    UNUSED_RESULT(seteuid(0));

    s = su_socket(su.sa.sa_family, SOCK_STREAM, ctx->protocol);
    if (s < 0) {
	logerr("socket (%s:%d)", __FILE__, __LINE__);
	UNUSED_RESULT(seteuid(ctx->uid));
	DebugOut(DEBUG_COMMAND);
	return;
    }

    if (0 > su_bind(s, &su)) {
	logerr("bind (%s:%d)", __FILE__, __LINE__);
	UNUSED_RESULT(seteuid(ctx->uid));

	/* Binding to privileged port failed. Try some random port. */
	su_set_port(&su, 0);
	if (0 > su_bind(s, &su)) {
	    logerr("bind (%s:%d)", __FILE__, __LINE__);
	    close(s);
	    DebugOut(DEBUG_COMMAND);
	    return;
	}
    } else
	UNUSED_RESULT(seteuid(ctx->uid));

    if (0 > su_connect(s, &ctx->sa_d_remote))
	switch (errno) {
	case EINPROGRESS:
	    Debug((DEBUG_COMMAND, "  connect in progress\n"));
	    io_register(ctx->io, s, ctx);
	    io_set_cb_o(ctx->io, s, (void *) connect_data);
	    io_clr_cb_i(ctx->io, s);
	    io_set_cb_e(ctx->io, s, (void *) connect_data_failed);
	    io_set_cb_h(ctx->io, s, (void *) cleanup_data);
	    ctx->dfn = s;
	    io_sched_add(ctx->io, ctx, (void *) cleanup_data, ctx->conn_timeout, 0);
	    io_clr_i(ctx->io, s);
	    io_set_o(ctx->io, s);
	    break;
	default:
	    logerr("connect (%s:%d)", __FILE__, __LINE__);
	case ECONNREFUSED:
	    close(s);
    } else {
	/* connected */
	ctx->dfn = s;
	io_register(ctx->io, s, ctx);
	io_set_cb_h(ctx->io, s, (void *) cleanup_data);
	connect_data(ctx, s);
    }
    DebugOut(DEBUG_COMMAND);
}
