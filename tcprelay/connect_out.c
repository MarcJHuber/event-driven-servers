/*
 * connect_out.c
 * (C)1999-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

static int select_peer(struct context *ctx, int cur)
{
    static long count = 0;
    int i = 0;

    Debug((DEBUG_PROC, "select_peer\n"));

    if (rebalance && (count == rebalance))
	for (count = 0, i = 0; i < con_arr_len; i++)
	    con_arr[i].dead = 0;
    count++;

    for (i = 0; con_arr[i].dead && i < con_arr_len; i++)
	/* empty */ ;

    Debug((DEBUG_PROC, "#A i = %d\n", i));

    if (i < con_arr_len) {
	int min = i;
	int prio_min = (con_arr[i].use << 8) / con_arr[i].weight;
	Debug((DEBUG_PROC, "#  min == %d prio == %d\n", min, prio_min));
	i++;
	for (; i < con_arr_len; i++) {
	    int prio_cur = (con_arr[i].use << 8) / con_arr[i].weight;
	    Debug((DEBUG_PROC, "#B i == %d prio == %d\n", i, prio_cur));
	    if (prio_cur > -1 && prio_min > prio_cur) {
		min = i;
		prio_min = prio_cur;
	    }
	}
	Debug((DEBUG_PROC, "#C i = %d\n", min));
	ctx->con_arr_idx = min;
	con_arr[min].use++;
	return 0;
    }

    if (!ctx->failed) {
	/* all peers are dead -- try re-enabling ... */
	ctx->failed = 1;
	count = rebalance;
	return select_peer(ctx, cur);
    }

    return -1;
}

static void deactivate_peer(struct context *ctx, int cur __attribute__((unused)))
{
    if (ctx->con_arr_idx > -1) {
	con_arr[ctx->con_arr_idx].use--;
	con_arr[ctx->con_arr_idx].dead = 1;
	ctx->con_arr_idx = -1;
    }
}

static void peer_died(struct context *ctx, int cur)
{
    deactivate_peer(ctx, cur);
    if (ctx->ifn > -1) {
	int ifn = ctx->ifn;
	cleanup_one(ctx, ctx->ofn);
	ctx->ofn = -1;
	connect_out(ctx, ifn);
    } else
	cleanup(ctx, cur);
}


void connect_out(struct context *ctx, int cur)
{
    int s = -1;
    int bufsize = BUFSIZE + 512;

    DebugIn(DEBUG_COMMAND);

  again:

    if (s > -1) {
	close(s);
	s = -1;
    }

    if (select_peer(ctx, cur) || ctx->con_arr_idx < 0) {
	cleanup(ctx, cur);
	DebugOut(DEBUG_COMMAND);
	return;
    }

    s = su_socket(con_arr[ctx->con_arr_idx].sa.sa.sa_family, SOCK_STREAM, con_arr[ctx->con_arr_idx].protocol);
    fcntl(s, F_SETFD, fcntl(s, F_GETFD, 0) | FD_CLOEXEC);

    if (s < 0) {
	logerr("socket (%s:%d)", __FILE__, __LINE__);
	if (ctx->ifn > -1)
	    cleanup(ctx, ctx->ifn);
	DebugOut(DEBUG_COMMAND);
	return;
    }

    setsockopt(s, SOL_SOCKET, SO_SNDBUF, (char *) &bufsize, (socklen_t) sizeof(bufsize));
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, (char *) &bufsize, (socklen_t) sizeof(bufsize));

    if (lcladdr && 0 > su_bind(s, &(*lcladdr))) {
	logerr("bind (%s:%d)", __FILE__, __LINE__);
	close(s);
	if (ctx->ifn > -1)
	    cleanup(ctx, ctx->ifn);
	DebugOut(DEBUG_COMMAND);
	return;
    }

    if (su_connect(s, &con_arr[ctx->con_arr_idx].sa) < 0)
	switch (errno) {
	case EINPROGRESS:
	    io_register(ctx->io, s, ctx);
	    io_clr_cb_i(ctx->io, s);
	    io_set_cb_o(ctx->io, s, (void *) connected);
	    io_set_cb_h(ctx->io, s, (void *) peer_died);
	    io_set_cb_e(ctx->io, s, (void *) peer_died);
	    io_set_o(ctx->io, s);
	    ctx->ofn = s;
	    break;
	default:
	    logerr("connect (%s:%d)", __FILE__, __LINE__);
	    deactivate_peer(ctx, cur);
	    goto again;
    } else {
	/* connected */

	io_register(ctx->io, s, ctx);
	ctx->ofn = s;
	connected(ctx, s);
    }
    DebugOut(DEBUG_COMMAND);
}
