/*
 * set_proctitle.c
 * (C) 1999-2011 Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "mavis.h"
#include "set_proctitle.h"
#include "spawnd_headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

void set_proctitle(int status)
{
    switch (status) {
    case ACCEPT_YES:
	if (!common_data.singleprocess) {
	    setproctitle("%d connection%s", common_data.users_cur, common_data.users_cur == 1 ? "" : "s");
	    break;
	}
    case ACCEPT:
	setproctitle("%d connection%s, accepting up to %d more",
		     common_data.users_cur, common_data.users_cur == 1 ? "" : "s", common_data.users_max_total - common_data.users_cur);
	break;
    case ACCEPT_NO:
	setproctitle("%d connection%s, %s new ones", common_data.users_cur, common_data.users_cur == 1 ? "" : "s", spawnd_data.overload_hint);
	break;
    case ACCEPT_NEVER:
	setproctitle("%d connection%s left, dying when idle", common_data.users_cur, common_data.users_cur == 1 ? "" : "s");
	break;
    }
}
