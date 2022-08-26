/*
 * h_site_chmod.c
 *
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

void h_site_chmod(struct context *ctx, char *arg)
{
    char *t;
    struct stat st;
    u_int mode;
    u_int mode_add = 0;
    u_int mode_del = 0;
    int numeric = -1;

    DebugIn(DEBUG_COMMAND);

    t = arg;

    while (*arg && !isspace((int) *arg))
	arg++;

    if (!isspace((int) *arg)) {
	reply(ctx, MSG_500_arguments_required);
	DebugOut(DEBUG_COMMAND);
	return;
    }

    *arg++ = 0;

    if (1 != sscanf(t, "%o", &mode)) {
	numeric = 0;
	mode = 0;
	while (*t) {
	    u_int bits_affected = 0;
	    u_int new_mode = 0;
	    char op = 0;

	    for (; *t && *t != ','; t++)
		if (op)
		    switch (*t) {
		    case 'r':
			new_mode |= 0444;
			break;
		    case 'w':
			new_mode |= 0222;
			break;
		    case 'x':
			new_mode |= 0111;
			break;
		    default:
		      invalid_mode:
			reply(ctx, MSG_500_invalid_mode);
			DebugOut(DEBUG_COMMAND);
			return;
		} else
		    switch (*t) {
		    case '+':
		    case '-':
		    case '=':
			op = *t;
			if (!bits_affected)
			    bits_affected = ~ctx->umask & 0777;
			break;
		    case 'u':
			bits_affected |= 0700;
			break;
		    case 'g':
			bits_affected |= 070;
			break;
		    case 'o':
			bits_affected |= 07;
			break;
		    case 'a':
			bits_affected = 0777;
			break;
		    default:
			goto invalid_mode;
		    }

	    new_mode &= bits_affected;
	    switch (op) {
	    case '+':
		mode_add |= new_mode;
		mode_del &= ~new_mode;
		break;
	    case '-':
		mode_del |= new_mode;
		mode_add &= ~new_mode;
		break;
	    case '=':
		mode_add |= new_mode;
		mode_del &= ~new_mode;
		mode_del |= ~new_mode & bits_affected;
		break;
	    default:
		goto invalid_mode;
	    }
	    if (*t)
		t++;
	}
    }

    while (isspace((int) *arg))
	arg++;

    if (!*arg)
	reply(ctx, MSG_500_missing_filename);
    else if ((t = buildpath(ctx, arg)) &&
	     !pickystat(ctx, &st, t) &&
	     (S_ISREG(st.st_mode) || S_ISDIR(st.st_mode)) &&
	     !chmod(t, numeric ? mode : ((st.st_mode & ~mode_del) | mode_add) | (st.st_mode & (S_ISDIR(st.st_mode)
											       ? ctx->chmod_dirmask : ctx->chmod_filemask))))
	reply(ctx, MSG_200_permissions_changed);
    else
	reply(ctx, MSG_550_Permission_denied);

    DebugOut(DEBUG_COMMAND);
}
