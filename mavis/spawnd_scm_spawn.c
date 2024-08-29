/*
 * scm_spawn.c
 *
 * (C)2000-2011 Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 */

#include "misc/sysconf.h"
#include "spawnd_headers.h"
#include <grp.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>
#include <sysexits.h>

static const char rcsid[] __attribute__((used)) = "$Id$";

void spawnd_cleanup_internal(struct spawnd_context *ctx, int fd __attribute__((unused)))
{
    DebugIn(DEBUG_PROC);

    io_close(ctx->io, ctx->fn);

    while (io_sched_pop(ctx->io, ctx));

    if (ctx->is_listener)
	spawnd_data.listeners_max--;
    else {
	int i;
	common_data.users_cur -= ctx->use;
	for (i = 0; i < common_data.servers_cur && ctx != spawnd_data.server_arr[i]; i++);
	if (i < --common_data.servers_cur)
	    spawnd_data.server_arr[i] = spawnd_data.server_arr[common_data.servers_cur];
        spawnd_data.server_arr[common_data.servers_cur] = NULL;
	set_proctitle(ACCEPT);
    }

    free(ctx);

    DebugOut(DEBUG_PROC);
}

int spawnd_spawn_child(pid_t * pidp)
{
    int socks[2];
    pid_t pid;
    int flags;
    int bufsize = spawnd_data.scm_bufsize;
    int one = 1;
    char *argv[10];
    int i = 0;
    char *deb = alloca(20);

    memset(&argv, 0, sizeof(argv));

    argv[i++] = spawnd_data.child_path;
    if (common_data.version_only)
	argv[i++] = "-v";
    if (common_data.parse_only)
	argv[i++] = "-P";
    if (common_data.debug) {
	argv[i++] = "-d";
	snprintf(deb, 20, "%u", common_data.debug);
	argv[i++] = deb;
    }
    argv[i++] = spawnd_data.child_config;
    argv[i++] = spawnd_data.child_id;
    argv[i++] = NULL;

    if (socketpair(PF_UNIX, SOCK_DGRAM, 0, socks)) {
	logerr("socketpair (%s:%d)", __FILE__, __LINE__);
	exit(EX_OSERR);
    }

    switch ((pid = fork())) {
    case 0:
	// io_destroy(common_data.io, NULL);
	close(socks[0]);
	dup2(socks[1], 0);
	close(socks[1]);
	if (bufsize) {
	    setsockopt(0, SOL_SOCKET, SO_SNDBUF, (char *) &bufsize, (socklen_t) sizeof(bufsize));
	    setsockopt(0, SOL_SOCKET, SO_RCVBUF, (char *) &bufsize, (socklen_t) sizeof(bufsize));
	}
	setsockopt(0, SOL_SOCKET, SO_KEEPALIVE, (char *) &one, (socklen_t) sizeof(one));

	if (common_data.parse_only)
	    execv(spawnd_data.child_path, argv);
	else {
	    if (spawnd_data.uid)
		setgroups(0, NULL);

	    if (spawnd_data.gid && setgid(spawnd_data.gid))
		logerr("Can't set group id to %d", (int) spawnd_data.gid);

	    if (spawnd_data.uid && setuid(spawnd_data.uid))
		logerr("Can't set user id to %d", (int) spawnd_data.uid);

	    if (spawnd_data.cwd && chdir(spawnd_data.cwd))
		logerr("Can't chdir to %s", spawnd_data.cwd);

	    execv(spawnd_data.child_path, argv);
	}

	logerr("execl (%s, ...) (%s:%d)", spawnd_data.child_path, __FILE__, __LINE__);
	if (!strchr(spawnd_data.child_path, '/'))
	    logmsg("Try calling %s with its absolute path, and this " "problem will go away.", spawnd_data.child_path);
	exit(EX_OSERR);
    case -1:
	logerr("fork (%s:%d)", __FILE__, __LINE__);
	exit(EX_OSERR);
    default:
	close(socks[1]);
	flags = fcntl(socks[0], F_GETFD, 0) | FD_CLOEXEC;
	fcntl(socks[0], F_SETFD, flags);
	if (bufsize) {
	    setsockopt(socks[0], SOL_SOCKET, SO_SNDBUF, (char *) &bufsize, (socklen_t) sizeof(bufsize));
	    setsockopt(socks[0], SOL_SOCKET, SO_RCVBUF, (char *) &bufsize, (socklen_t) sizeof(bufsize));
	}
	setsockopt(socks[0], SOL_SOCKET, SO_KEEPALIVE, (char *) &one, (socklen_t) sizeof(one));
	if (pidp)
	    *pidp = pid;

	return socks[0];
    }
}

static void recv_childmsg(struct spawnd_context *ctx, int cur)
{
    int max = -1;
    struct scm_data_accept sd;
    int result = common_data.scm_recv_msg(cur, &sd, sizeof(sd), NULL);

    if (result)
	spawnd_cleanup_internal(ctx, cur);
    else
	switch (sd.type) {
	case SCM_DONE:
	    common_data.users_cur--, ctx->use--;
	    if (spawnd_data.listeners_inactive) {
		int i;
		logmsg("resuming normal operation");
		spawnd_data.listeners_inactive = 0;
		switch (spawnd_data.overload) {
		case S_queue:
		    for (i = 0; i < spawnd_data.listeners_max; i++) {
			if (spawnd_data.listener_arr[i]->listen_backlog != spawnd_data.listener_arr[i]->overload_backlog)
			    listen(spawnd_data.listener_arr[i]->fn, spawnd_data.listener_arr[i]->listen_backlog);
			io_set_i(ctx->io, spawnd_data.listener_arr[i]->fn);
		    }
		    break;
		case S_reset:
		    for (i = 0; i < spawnd_data.listeners_max; i++)
			spawnd_bind_listener(spawnd_data.listener_arr[i], spawnd_data.listener_arr[i]->fn);
		    break;
		default:;
		}
	    }
	    set_proctitle(ACCEPT);
	    break;
	case SCM_BAD_CFG:
	    logmsg("Child reported fatal configuration problem. Exiting.");
	    exit(EX_CONFIG);
	case SCM_DYING:
	    spawnd_cleanup_internal(ctx, cur);
	    break;
	case SCM_MAX:
	    max = ((struct scm_data_max *) (&sd))->max;
	    if (common_data.users_max > max) {
		common_data.users_max = max;
		logmsg("child limits maximum number of users to %d", common_data.users_max);
		set_proctitle(ACCEPT);
	    }
	    break;
	case SCM_KEEPALIVE:
	    break;
	default:
	    logmsg("Child used unknown message type %d", (int) sd.type);
	}
}

void spawnd_add_child()
{
    if (common_data.servers_cur < common_data.servers_max) {
	pid_t pid;
	int cur = spawnd_spawn_child(&pid);
	if (cur > -1) {
	    struct spawnd_context *ctx = spawnd_new_context(common_data.io);
	    ctx->pid = pid;
	    ctx->fn = cur;
	    ctx->tv = io_now;

	    io_register(common_data.io, cur, ctx);
	    io_set_cb_i(common_data.io, cur, (void *) recv_childmsg);
	    io_set_cb_h(common_data.io, cur, (void *) spawnd_cleanup_internal);
	    io_set_cb_e(common_data.io, cur, (void *) spawnd_cleanup_internal);
	    io_clr_cb_o(common_data.io, cur);
	    io_set_i(common_data.io, cur);
	    spawnd_data.server_arr[common_data.servers_cur++] = ctx;
	}
    }
}
