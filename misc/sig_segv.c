/*
 * sig_segv.c (C)1999-2011 by Marc Huber <Marc.Huber@web.de>
 *
 * $Id$
 *
 */

#ifndef __GNUC__
#define __attribute__(A)
#endif				/* __GNUC__ */

static const char rcsid[] __attribute__((used)) = "$Id$";

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sysexits.h>
#include <signal.h>
#include <limits.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include "misc/sysconf.h"
#include "misc/memops.h"
#include "mavis/log.h"
#include "misc/sig_segv.h"
#include "misc/version.h"
#ifdef HAVE_EXECINFO_H
#include <execinfo.h>
#endif

static char *coredumpdir = NULL;
static char *gcorecmd = NULL;
static char *gdbcmd = NULL;

#ifdef SA_SIGINFO
void (*coredump_handler)(int, siginfo_t *, void *);

void catchsegv(int sig __attribute__((unused)), siginfo_t * sip __attribute__((unused)), void *uap __attribute__((unused)))
#else
void (*coredump_handler)(int);

void catchsegv(int sig __attribute__((unused)))
#endif
{
    char buf[1024];
    FILE *g;

    logmsg("Catched SIGSEGV");
    logmsg("Apologies ... this shouldn't have happened. Please verify that");
    logmsg("you are running the most current version from");
    logmsg("    https://github.com/MarcJHuber/event-driven-servers/");
    logmsg("The version you're currently running is " VERSION);
    logmsg("If this issue persists even with the most recent version:");
    logmsg("Reconfigure with --ggdb, recompile and reinstall. Then send");
    logmsg("a bug report via GitHub issues at");
    logmsg("    https://github.com/MarcJHuber/event-driven-servers/issues");
    logmsg("and include the backtraces.");
    logmsg("Please do NOT mail bug reports to the private mail address of");
    logmsg("the author, unless you have a prior permit for that.");
    logmsg("Thank you.");

    snprintf(buf, sizeof(buf), "CRASHPID=%lu", (long unsigned) getpid());
    putenv(buf);

#ifdef HAVE_EXECINFO_H
    {
	void *array[40];
	int len = backtrace(array, 40);
	char **c = backtrace_symbols(array, len);
	logmsg("EXECINFO: backtrace start");
	while (len-- > 0)
	    logmsg("EXECINFO: %d %s", len, c[len]);
	logmsg("EXECINFO: backtrace end");
    }
#endif				/* HAVE_EXECINFO_H */

    if (!gdbcmd)
	gdbcmd = "(printf 'bt\nq\n';sleep 3)|gdb -n -q -p $CRASHPID 2>/dev/null";
    g = popen(gdbcmd, "r");
    if (g) {
	logmsg("GDB: running: \"%s\"", gdbcmd);
	logmsg("GDB: backtrace start");
	while (fgets(buf, sizeof(buf), g))
	    logmsg("GDB: %s", buf);
	pclose(g);
	logmsg("GDB: backtrace end");
    }
#ifdef EXC_BAD_INSTRUCTION
    signal(EXC_BAD_INSTRUCTION, SIG_DFL);
#endif
#ifdef SIGBUS
    signal(SIGBUS, SIG_DFL);
#endif
    signal(SIGSEGV, SIG_DFL);

    if (coredumpdir) {
	struct rlimit rlim;
	char cdf[PATH_MAX];

	snprintf(cdf, sizeof(cdf), "%s/core.%.8lx", coredumpdir, (u_long) time(NULL));

	UNUSED_RESULT(seteuid(getuid()));
	UNUSED_RESULT(setegid(getgid()));

	if (getrlimit(RLIMIT_CORE, &rlim)) {
	    logerr("getrlimit (%s:%d)", __FILE__, __LINE__);
	    exit(EX_OSERR);
	}

	rlim.rlim_cur = rlim.rlim_max;
	setrlimit(RLIMIT_CORE, &rlim);

	if (chdir(coredumpdir)) {
	    logerr("SIGSEGV: chdir(%s) (%s:%d)", coredumpdir, __FILE__, __LINE__);
	    exit(EX_NOPERM);
	}

	rename("core", cdf);
	logmsg("SIGSEGV: Trying to dump core in %s", coredumpdir);

	if (gcorecmd) {
	    g = popen(gcorecmd, "r");
	    if (g) {
		while (fgets(buf, sizeof(buf), g))
		    logmsg("GCORE: %s", buf);
		pclose(g);
	    }
	} else
	    abort();
    }
    exit(EX_UNAVAILABLE);
}

void setup_sig_segv(char *coredump_dir, char *gcore_cmd, char *debug_cmd)
{
    struct sigaction sa;

    if (coredump_dir)
	coredumpdir = Xstrdup(coredump_dir);
    if (gcore_cmd)
	gcorecmd = Xstrdup(gcore_cmd);
    if (debug_cmd)
	gdbcmd = Xstrdup(debug_cmd);

    sigaction(SIGSEGV, NULL, &sa);
#ifdef SA_SIGINFO
    coredump_handler = sa.sa_sigaction;
    sa.sa_sigaction = catchsegv;
    sa.sa_flags |= SA_SIGINFO;
#else
    coredump_handler = sa.sa_handler;
    sa.sa_handler = catchsegv;
#endif
    if (!gcorecmd) {
#ifdef SA_NOMASK
	sa.sa_flags |= SA_NOMASK;
#endif				/* SA_NOMASK */
#ifdef SA_NODEFER
	sa.sa_flags |= SA_NODEFER;
#endif				/* SA_NODEFER */
	;
    }
#ifdef EXC_BAD_INSTRUCTION
    sigaction(EXC_BAD_INSTRUCTION, &sa, NULL);
#endif
#ifdef SIGBUS
    sigaction(SIGBUS, &sa, NULL);
#endif
    sigaction(SIGSEGV, &sa, NULL);
}
