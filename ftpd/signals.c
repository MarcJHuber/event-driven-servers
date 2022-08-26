/*
 * signals.c
 * (C)1999-2011 by Marc Huber <Marc.Huber@web.de>
 *
 * $Id$
 *
 */

#include "headers.h"
#include <signal.h>
#include <sysexits.h>

static const char rcsid[] __attribute__((used)) = "$Id$";

static sigset_t master_set;

void catchhup(int i __attribute__((unused)))
{
    signal(SIGHUP, SIG_IGN);
    signal(SIGTERM, SIG_IGN);

    cleanup(ctx_spawnd, 0);
    die_when_idle = -1;
    logmsg("SIGHUP: No longer accepting new connections.");

    set_proctitle(ACCEPT_NEVER);
}

void catchalrm(int i __attribute__((unused)))
{
}

void setup_signals()
{
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, catchhup);
    signal(SIGTERM, catchhup);
    signal(SIGALRM, catchalrm);
    sigfillset(&master_set);
    sigdelset(&master_set, SIGSEGV);
    sigprocmask(SIG_SETMASK, &master_set, NULL);
}

void process_signals()
{
    sigprocmask(SIG_UNBLOCK, &master_set, NULL);
    sigprocmask(SIG_SETMASK, &master_set, NULL);
}
