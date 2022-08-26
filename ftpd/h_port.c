/*
 * h_port.c
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

#define MODE_PORT 0
#define MODE_LPRT 1
#define MODE_EPRT 2

static char *modelist[] = { "PORT", "LPRT", "EPRT" };

static void do_port(int mode, struct context *ctx, char *arg)
{
    int af_d;

    DebugIn(DEBUG_COMMAND);

    if (ctx->dfn > -1)
	cleanup_data(ctx, ctx->dfn);

    if (ctx->epsv_all) {
	reply(ctx, MSG_500_EPSV_only);
	DebugOut(DEBUG_COMMAND);
	return;
    }

    switch (mode) {
    case MODE_LPRT:
	af_d = foobar_eval(&ctx->sa_d_remote, arg);
	break;
    case MODE_EPRT:
	af_d = rfc2428_eval(&ctx->sa_d_remote, arg);
	break;
    default:
	af_d = rfc959_eval(&ctx->sa_d_remote, arg);
    }

    if (af_d == -2) {
	char buf[160];
	switch (mode) {
	case MODE_LPRT:
	    replyf(ctx, MSG_521_Supported_AF, print_foobar_families(buf, sizeof(buf)));
	    break;
	case MODE_EPRT:
	    replyf(ctx, MSG_522_Supported_AF, print_rfc2428_families(buf, sizeof(buf)));
	}
	DebugOut(DEBUG_COMMAND);
	return;
    }

    if (af_d < 0)
	reply(ctx, MSG_501_Syntax_error);
    /* rfc2577 suggests to deny connections to reserved ports: */
    else if (su_get_port(&ctx->sa_d_remote) < IPPORT_RESERVED) {
	ctx->sa_d_remote = ctx->sa_c_remote;
	reply(ctx, MSG_504_Command_not_implemented);
    } else if (!ctx->address_mismatch && !su_equal_addr(&ctx->sa_d_remote, &ctx->sa_c_remote))
	replyf(ctx, MSG_501_port_denied, modelist[mode]);
    else
	replyf(ctx, MSG_200_port_successful, modelist[mode]);

    DebugOut(DEBUG_COMMAND);
}

void h_port(struct context *ctx, char *arg)
{
    do_port(MODE_PORT, ctx, arg);
}

void h_lprt(struct context *ctx, char *arg)
{
    do_port(MODE_LPRT, ctx, arg);
}

void h_eprt(struct context *ctx, char *arg)
{
    do_port(MODE_EPRT, ctx, arg);
}
