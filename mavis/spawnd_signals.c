/*
 * signals.c (C)1999-2011 by Marc Huber <Marc.Huber@web.de>
 *
 * $Id$
 *
 */

#include "spawnd_headers.h"
#include "misc/sysconf.h"
#include <sysexits.h>
#ifdef __linux__
#include <sys/ioctl.h>
#include <linux/sockios.h>
#endif

static const char rcsid[] __attribute__((used)) = "$Id$";

static sigset_t master_set;

/*
 * A worker that writes to the master after the master is gone makes the
 * kernel discard what is still queued for it, connections passed with
 * SCM_ACCEPT included, and these are reset. So before going away, give the
 * workers up to a second to read their queues, SCM_MAY_DIE being the last
 * message in them.
 */
static void wait_for_servers(void)
{
#ifdef SIOCOUTQ
    for (int k = 0; k < 100; k++) {
	int queued = 0;
	for (int j = 0; j < common_data.servers_cur && !queued; j++)
	    if (ioctl(spawnd_data.server_arr[j]->fn, SIOCOUTQ, &queued))
		queued = 0;
	if (!queued)
	    return;
	usleep(10000);
    }
#endif
}

static void catchhup(int i __attribute__((unused)))
{
    struct scm_data sd = {.type = SCM_MAY_DIE };
    for (int j = 0; j < common_data.servers_cur; j++)
	common_data.scm_send_msg(spawnd_data.server_arr[j]->fn, &sd, -1);
    wait_for_servers();

    logmsg("SIGHUP: restarting");
    pid_unlink(&common_data.pidfile);
    execve(common_data.progpath, common_data.argv, spawnd_keep_listeners());
    exit(EX_OSERR);
}

static void catchterm(int i __attribute__((unused)))
{
    struct scm_data sd = {.type = SCM_MAY_DIE };
    for (int j = 0; j < common_data.servers_cur; j++)
	common_data.scm_send_msg(spawnd_data.server_arr[j]->fn, &sd, -1);
    wait_for_servers();

    logmsg("SIGTERM: exiting");
    pid_unlink(&common_data.pidfile);
    exit(EX_OK);
}

static void catchusr1(int sig __attribute__((unused)))
{
    spawnd_data.abandon = 1;
}

void spawnd_setup_signals()
{
    struct sigaction sa;

    signal(SIGPIPE, SIG_IGN);
//    signal(SIGCHLD, SIG_IGN);
    if (spawnd_data.inetd)
	signal(SIGHUP, catchterm);
    else
	signal(SIGHUP, catchhup);
    signal(SIGINT, catchterm);
    signal(SIGTERM, catchterm);
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = catchusr1;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGUSR1, &sa, NULL);

    sigfillset(&master_set);
    sigdelset(&master_set, SIGSEGV);
    sigdelset(&master_set, SIGTERM);
    sigdelset(&master_set, SIGINT);
    sigdelset(&master_set, SIGUSR1);
    if (spawnd_data.inetd)
	sigdelset(&master_set, SIGHUP);
    sigprocmask(SIG_SETMASK, &master_set, NULL);
}

void spawnd_process_signals()
{
    sigprocmask(SIG_UNBLOCK, &master_set, NULL);
    sigprocmask(SIG_SETMASK, &master_set, NULL);
}
