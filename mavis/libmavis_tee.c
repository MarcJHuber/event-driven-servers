/*
 * libmavis_tee.c
 * (C)2002-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 * 
 * $Id$
 *
 */

#define MAVIS_name "tee"

#include "misc/sysconf.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <dlfcn.h>
#include <sys/time.h>
#include <unistd.h>

#include "misc/io.h"
#include "debug.h"
#include "log.h"
#include "misc/strops.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

#define MAVIS_CTX_PRIVATE	\
		int fd_in;	\
		int fd_out;	\
		char *path_in;	\
		char *path_out;	\
		uid_t uid;	\
		gid_t gid;	\
		mode_t mode;

#include "mavis.h"

#define HAVE_mavis_init_in
static int mavis_init_in(mavis_ctx * mcx)
{
    DebugIn(DEBUG_MAVIS);

    if (!mcx->path_in && !mcx->path_out)
	logmsg("Warning: %s module lacks path definition", MAVIS_name);
    else {
	uid_t euid = geteuid();
	gid_t egid = getegid();

	UNUSED_RESULT(setegid(mcx->gid));
	UNUSED_RESULT(seteuid(mcx->uid));

	if (mcx->path_in) {
	    mcx->fd_in = open(mcx->path_in, O_CREAT | O_WRONLY | O_APPEND, mcx->mode);
	    if (mcx->fd_in < -1)
		logerr("Warning: %s: open(%s)", MAVIS_name, mcx->path_in);
	    else
		fcntl(mcx->fd_in, F_SETFD, FD_CLOEXEC);
	}
	if (mcx->path_out) {
	    if (mcx->path_in && strcmp(mcx->path_in, mcx->path_out)) {
		mcx->fd_out = open(mcx->path_out, O_CREAT | O_WRONLY | O_APPEND, mcx->mode);
		if (mcx->fd_out < -1)
		    logerr("Warning: %s: open(%s)", MAVIS_name, mcx->path_out);
		else
		    fcntl(mcx->fd_out, F_SETFD, FD_CLOEXEC);
	    } else if (mcx->fd_in > -1)
		mcx->fd_out = mcx->fd_in;
	}
	UNUSED_RESULT(seteuid(euid));
	UNUSED_RESULT(setegid(egid));
    }

    DebugOut(DEBUG_MAVIS);
    return MAVIS_INIT_OK;
}

/*
mavis path =...mavis module = tee - id {
    module = <modulename >
	user - id =...group - id =...mode =...path(in | out) =...
}
*/

#define HAVE_mavis_parse_in
static int mavis_parse_in(mavis_ctx * mcx, struct sym *sym)
{
    while (1) {
	switch (sym->code) {
	case S_script:
	    mavis_script_parse(mcx, NULL, sym);
	    continue;
	case S_userid:
	    parse_userid(sym, &mcx->uid, &mcx->gid);
	    continue;
	case S_groupid:
	    parse_groupid(sym, &mcx->gid);
	    continue;
	case S_path:
	    sym_get(sym);
	    switch (sym->code) {
	    case S_in:
		sym_get(sym);
		parse(sym, S_equal);
		strset(&mcx->path_in, sym->buf);
		sym_get(sym);
		continue;
	    case S_out:
		sym_get(sym);
		parse(sym, S_equal);
		strset(&mcx->path_out, sym->buf);
		sym_get(sym);
		continue;
	    case S_equal:
		sym_get(sym);
		if (!mcx->path_in)
		    strset(&mcx->path_in, sym->buf);
		if (!mcx->path_out)
		    strset(&mcx->path_out, sym->buf);
		sym_get(sym);
		continue;
	    default:
		parse_error_expect(sym, S_equal, S_in, S_out, S_unknown);
	    }
	case S_mode:
	    parse_umask(sym, &mcx->mode);
	    continue;
	case S_eof:
	case S_closebra:
	    return MAVIS_CONF_OK;
	case S_action:
	    mavis_module_parse_action(mcx, sym);
	    continue;
	default:
	    parse_error_expect(sym, S_script, S_userid, S_groupid, S_path, S_mode, S_action, S_closebra, S_unknown);
	}
    }
}

#define HAVE_mavis_drop_in
static void mavis_drop_in(mavis_ctx * mcx)
{
    Xfree(&mcx->path_in);
    Xfree(&mcx->path_out);
    if (mcx->fd_in == mcx->fd_out)
	mcx->fd_out = -1;
    if (mcx->fd_in > -1)
	close(mcx->fd_in);
    if (mcx->fd_out > -1)
	close(mcx->fd_out);
}

static void write_av(mavis_ctx * mcx, int fd, av_ctx ** ac)
{
    char buf[65536];
    char *b = buf;
    ssize_t l = av_array_to_char(*ac, buf,
				 sizeof(buf) - 3, NULL);
    if (l > -1) {
	strcpy(buf + l, "=\n");
	l += 2;
	while (l > 0) {
	    ssize_t i = Write(fd, b, (size_t) l);
	    if (i < 0) {
		logerr("Warning: %s: write", MAVIS_name);
		close(fd);
		if (fd == mcx->fd_in)
		    mcx->fd_in = -1;
		if (fd == mcx->fd_out)
		    mcx->fd_out = -1;
		return;
	    }
	    l -= i, b += i;
	}
    }
}

#define HAVE_mavis_send_in
static int mavis_send_in(mavis_ctx * mcx, av_ctx ** ac)
{
    if (mcx->fd_in > -1)
	write_av(mcx, mcx->fd_in, ac);
    return MAVIS_DOWN;
}

#define HAVE_mavis_recv_out
static int mavis_recv_out(mavis_ctx * mcx, av_ctx ** ac)
{
    if (mcx->fd_out > -1)
	write_av(mcx, mcx->fd_out, ac);
    return MAVIS_DOWN;
}

#define HAVE_mavis_new
static void mavis_new(mavis_ctx * mcx)
{
    mcx->mode = 0600;
}

#include "mavis_glue.c"
