/*
 * h_prot.c
 *
 * (C)2000-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"
#include <ctype.h>

static const char rcsid[] __attribute__((used)) = "$Id$";

void h_prot(struct context *ctx, char *arg)
{
    DebugIn(DEBUG_COMMAND);

    if (ctx->protected_buffer_size)
	reply(ctx, MSG_503_PBSZ_INCOMPLETE);
    else
	switch (tolower((int) *arg)) {
	case 'c':
	    ctx->use_tls_d = 0;
	    reply(ctx, MSG_200_PROT_C_APPLIED);
	    break;
	case 'p':
	    ctx->use_tls_d = 1;
	    reply(ctx, MSG_200_PROT_P_APPLIED);
	    break;
	default:
	    reply(ctx, MSG_536_PROT_UNDEFINED);
	}
    DebugOut(DEBUG_COMMAND);
}
