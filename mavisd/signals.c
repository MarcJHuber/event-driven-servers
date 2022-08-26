/*
 * signals.c
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#ifndef __GNUC__
#define __attribute__(A)
#endif				/* __GNUC__ */

static const char rcsid[] __attribute__((used)) = "$Id$";

#include "mavisd/headers.h"
#include "misc/memops.h"
#include <sysexits.h>

void catchterm(int a __attribute__((unused)))
{
    logmsg("SIGTERM: Terminating");
    mavis_drop(mcx);
    pid_unlink(&common_data.pidfile);
    exit(EX_OK);
}

void setup_signals()
{
    signal(SIGTERM, catchterm);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
}
