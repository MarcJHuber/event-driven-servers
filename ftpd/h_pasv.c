/*
 * h_pasv.c
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

#define MODE_PASV 0
#define MODE_LPSV 1
#define MODE_EPSV 2

static void do_passive(int mode, struct context *ctx, char *arg)
{
    sockaddr_union sin;
    int s, port;
    socklen_t sinlen = (socklen_t) sizeof(sin);
    char buf[160];

    DebugIn(DEBUG_COMMAND);

    if (mode != MODE_EPSV && ctx->epsv_all) {
	reply(ctx, MSG_500_EPSV_only);
	DebugOut(DEBUG_COMMAND);
	return;
    }

    if (mode == MODE_PASV && ctx->sa_c_local.sa.sa_family != AF_INET) {
	reply(ctx, MSG_500_PASV_is_V4);
	DebugOut(DEBUG_COMMAND);
	return;
    }

    if (arg && (mode == MODE_EPSV)) {
	if (!strcasecmp(arg, "ALL")) {
	    reply(ctx, MSG_200_EPSV_only);
	    ctx->epsv_all = 1;
	} else {
/*
 * Allowing the client to select the data channel protocol we're going to
 * use seems weird, least to say. Don't do it, but claim that the request
 * did succeed.
 */
	    int family = rfc2428_2_af(atoi(arg));

	    if (family < 0)
		replyf(ctx, MSG_522_Network_proto_unsupported, print_rfc2428_families(buf, sizeof(buf)));
	    else
		replyf(ctx, MSG_200_Using_network_proto, af2rfc2428(family));
	}
	DebugOut(DEBUG_COMMAND);
	return;
    }

    cleanup_data(ctx, ctx->dfn);
    cleanup_file(ctx, ctx->ffn);

    sin = ctx->sa_c_local;

    if ((s = socket(ctx->sa_c_local.sa.sa_family, SOCK_STREAM, ctx->protocol)) < 0) {
	logerr("socket (%s:%d)", __FILE__, __LINE__);
	reply(ctx, MSG_451_Internal_error);
	DebugOut(DEBUG_COMMAND);
	return;
    }
    fcntl(s, F_SETFL, O_NONBLOCK);
    fcntl(s, F_SETFD, FD_CLOEXEC);

    if (ctx->pasv_ports_first == DEFAULT_PASV_PORTS_FIRST && ctx->pasv_ports_last == DEFAULT_PASV_PORTS_LAST) {
	su_set_port(&sin, 0);

	if (0 > su_bind(s, &sin)) {
	    logerr("bind (%s:%d)", __FILE__, __LINE__);
	    close(s);
	    reply(ctx, MSG_451_Internal_error);
	    DebugOut(DEBUG_COMMAND);
	    return;
	}
    } else {
	for (port = ctx->pasv_ports_last; port >= ctx->pasv_ports_first; port--)
	    if (su_set_port(&sin, port), su_bind(s, &sin) > -1)
		break;

	if (port < ctx->pasv_ports_first)
	    for (port = ctx->pasv_ports_last; port >= ctx->pasv_ports_first; port--)
		if (su_set_port(&sin, port), su_bind(s, &sin) > -1)
		    break;

	if (port < ctx->pasv_ports_first) {
	    logerr("bind (%s:%d)", __FILE__, __LINE__);
	    close(s);
	    reply(ctx, MSG_451_Internal_error);
	    DebugOut(DEBUG_COMMAND);
	    return;
	}
    }

    getsockname(s, &sin.sa, &sinlen);

    listen(s, 5);

    io_register(ctx->io, s, ctx);
    io_set_cb_i(ctx->io, s, (void *) accept_data);
    io_clr_cb_o(ctx->io, s);
    io_set_cb_e(ctx->io, s, (void *) cleanup_data);
    io_set_cb_h(ctx->io, s, (void *) cleanup_data);
    ctx->dfn = s;
    io_sched_add(ctx->io, ctx, (void *) cleanup_data, ctx->accept_timeout, 0);

    if (ctx->passive_addr)
	su_copy_addr(&sin, ctx->passive_addr);

    switch (mode) {
    case MODE_EPSV:
	replyf(ctx, MSG_229_Entering_EPSV, su_get_port(&sin));
	break;
    case MODE_LPSV:
	replyf(ctx, MSG_228_Entering_LPSV, foobar_str(&sin, buf, sizeof(buf)));
	break;
    default:
	replyf(ctx, MSG_227_Entering_PASV, rfc959_str(&sin, buf, sizeof(buf)));
    }

    ctx->passive_transfer = 1;

    DebugOut(DEBUG_COMMAND);
}

void h_lpsv(struct context *ctx, char *arg)
{
    do_passive(MODE_LPSV, ctx, arg);
}

void h_epsv(struct context *ctx, char *arg)
{
    do_passive(MODE_EPSV, ctx, arg);
}

void h_pasv(struct context *ctx, char *arg)
{
    do_passive(MODE_PASV, ctx, arg);
}
