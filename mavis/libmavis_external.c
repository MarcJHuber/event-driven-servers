/*
 * libmavis_external.c
 * (C)2001-2015 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 * 
 * $Id$
 */

#define MAVIS_name "external"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <dlfcn.h>
#include <sys/time.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

#include "misc/memops.h"
#include "debug.h"
#include "log.h"
#include "misc/strops.h"
#include "misc/crc32.h"
#include "misc/rb.h"
#include "misc/io.h"
#include "misc/io_sched.h"
#include "misc/io_child.h"
#include "misc/ostype.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

#define REAPMAX 30		/* terminated child history table size */
#define REAPINT 30		/* terminated child interval (seconds) */

#define MAVIS_CTX_PRIVATE			\
  struct io_context *io_context_local;		\
  struct io_context *io_context_parent;		\
  char *path;					\
  char **argv;					\
  int argc;					\
  int child_cur;				\
  int child_min;				\
  int child_max;				\
  int ncx;					\
  struct context **cx;				\
  struct context_stat *cx_stat;			\
  int usage;					\
  u_int counter;				\
  rb_tree_t *backlog_fifo;			\
  rb_tree_t *backlog_serial;			\
  rb_tree_t *backlog_app_ctx;			\
  rb_tree_t *outgoing;				\
  rb_tree_t *junkcontexts;			\
  time_t lastdump;				\
  u_long backlog_cur;				\
  u_long backlog_max;				\
  u_long backlog_max_p;				\
  int envcount;					\
  char **env;					\
  uid_t uid;					\
  gid_t gid;					\
  char *home;					\
  int reapcur;					\
  time_t reaphist[REAPMAX];			\
  time_t startup_time;

#include "mavis.h"

struct context {
    mavis_ctx *mcx;
    pid_t pid;
    char b_in[66536];
    char b_out[66536];
    char b_err[8192];
    size_t b_in_len;
    size_t b_out_len;
    size_t b_err_len;
    size_t b_in_off;
    size_t b_out_off;
    size_t b_err_off;
    int fd_in;
    int fd_out;
    int fd_err;
    u_int in_use:1;
    u_int canceled:1;
    av_ctx *ac;
    int index;
    int result;
    unsigned long long counter;
};
struct context_stat {
    unsigned long startup;
    unsigned long startup_p;
    unsigned long long counter;
    unsigned long long counter_p;
};

static int fork_child(mavis_ctx *, int);

struct query {
    mavis_ctx *mcx;
    av_ctx *ac;
    av_ctx *ac_bak;
    time_t when;
    u_long counter;
    u_int serial_crc;
    u_int canceled:1;
    int result;
};

static int compare_fifo(const void *v1, const void *v2)
{
    if (((struct query *) v1)->when < ((struct query *) v2)->when)
	return -1;
    if (((struct query *) v1)->when > ((struct query *) v2)->when)
	return +1;
    if (((struct query *) v1)->counter < ((struct query *) v2)->counter)
	return -1;
    if (((struct query *) v1)->counter > ((struct query *) v2)->counter)
	return +1;
    if (((struct query *) v1)->serial_crc < ((struct query *) v2)->serial_crc)
	return -1;
    if (((struct query *) v1)->serial_crc > ((struct query *) v2)->serial_crc)
	return +1;
    if (((struct query *) v1)->ac->app_ctx < ((struct query *) v2)->ac->app_ctx)
	return -1;
    if (((struct query *) v1)->ac->app_ctx > ((struct query *) v2)->ac->app_ctx)
	return +1;
    return 0;
}

static int compare_serial(const void *v1, const void *v2)
{
    if (((struct query *) v1)->serial_crc < ((struct query *) v2)->serial_crc)
	return -1;
    if (((struct query *) v1)->serial_crc > ((struct query *) v2)->serial_crc)
	return +1;
    return strcmp(((struct query *) v1)->ac->arr[AV_A_SERIAL], ((struct query *) v2)->ac->arr[AV_A_SERIAL]);
}

static int compare_app_ctx(const void *v1, const void *v2)
{
    if (((struct query *) v1)->ac->app_ctx < ((struct query *) v2)->ac->app_ctx)
	return -1;
    if (((struct query *) v1)->ac->app_ctx > ((struct query *) v2)->ac->app_ctx)
	return +1;
    return 0;
}

static int compare_ctx(const void *v1, const void *v2)
{
    if (v1 < v2)
	return -1;
    if (v1 > v2)
	return +1;
    return 0;
}

static void free_payload(void *p)
{
    av_free(((struct query *) p)->ac);
    av_free(((struct query *) p)->ac_bak);
    free(p);
}

static void free_context(void *c)
{
    struct context *ctx = (struct context *) c;

    if (ctx->fd_err > -1)
	io_close(ctx->mcx->io, ctx->fd_err);
    if (ctx->fd_in > -1)
	io_close(ctx->mcx->io, ctx->fd_in);
    if (ctx->fd_out > -1)
	io_close(ctx->mcx->io, ctx->fd_out);
    free(ctx);
}

static void write_to_child(struct context *, int);

#define HAVE_mavis_init_in
static int mavis_init_in(mavis_ctx * mcx)
{
    int i;

    DebugIn(DEBUG_MAVIS);

    mcx->lastdump = mcx->startup_time = time(NULL);

    if (!mcx->path)
	logmsg("Warning: %s: module lacks path definition", MAVIS_name);
    else if (!mcx->argv[0]) {
	mcx->argv[0] = Xstrdup(basename(mcx->path));
	mcx->argv[1] = NULL;
    }

    if (mcx->child_min > mcx->child_max)
	mcx->child_min = mcx->child_max;

    if (!mcx->io_context_parent)
	mcx->io_context_local = mcx->io = io_init();
    mcx->cx = Xcalloc(mcx->child_max, sizeof(struct context *));
    mcx->cx_stat = Xcalloc(mcx->child_max, sizeof(struct context_stat));
    for (i = 0; i < mcx->child_min; i++)
	fork_child(mcx, i);

    mcx->backlog_serial = RB_tree_new(compare_serial, NULL);
    mcx->backlog_app_ctx = RB_tree_new(compare_app_ctx, NULL);
    mcx->backlog_fifo = RB_tree_new(compare_fifo, free_payload);
    mcx->outgoing = RB_tree_new(compare_app_ctx, free_payload);
    mcx->junkcontexts = RB_tree_new(compare_ctx, free_context);

    DebugOut(DEBUG_MAVIS);
    return MAVIS_INIT_OK;
}

/*
exec = path argv0 argv1 argv2...
setenv a = b
childs min = n
childs max = n
home = dir
user-id = uid
group-id = gid
*/
#define HAVE_mavis_parse_in
static int mavis_parse_in(mavis_ctx * mcx, struct sym *sym)
{
    u_int line;
    char *env_name;
    size_t len;
    struct stat st;

    while (1) {
	switch (sym->code) {
	case S_script:
	    mavis_script_parse(mcx, sym);
	    continue;
	case S_userid:
	    parse_userid(sym, &mcx->uid, &mcx->gid);
	    continue;
	case S_groupid:
	    parse_groupid(sym, &mcx->gid);
	    continue;
	case S_home:
	    sym_get(sym);
	    parse(sym, S_equal);
	    strset(&mcx->home, sym->buf);
	    sym_get(sym);
	    continue;
	case S_childs:
	    sym_get(sym);
	    switch (sym->code) {
	    case S_min:
		sym_get(sym);
		parse(sym, S_equal);
		mcx->child_min = parse_int(sym);
		continue;
	    case S_max:
		sym_get(sym);
		parse(sym, S_equal);
		mcx->child_max = parse_int(sym);
		continue;
	    default:
		parse_error_expect(sym, S_min, S_max, S_unknown);
	    }

	case S_setenv:
	    sym_get(sym);
	    env_name = alloca(strlen(sym->buf) + 1);
	    strcpy(env_name, sym->buf);
	    sym_get(sym);
	    parse(sym, S_equal);
	    len = strlen(env_name) + strlen(sym->buf) + 2;
	    mcx->env = Xrealloc(mcx->env, (mcx->envcount + 2) * sizeof(char *));
	    mcx->env[mcx->envcount] = Xcalloc(1, len);
	    snprintf(mcx->env[mcx->envcount++], len, "%s=%s", env_name, sym->buf);
	    mcx->env[mcx->envcount] = NULL;
	    sym_get(sym);
	    continue;

	case S_exec:{
		char buf[MAX_INPUT_LINE_LEN];
		sym_get(sym);
		parse(sym, S_equal);
		mcx->argv = calloc(1, sizeof(char *));
		line = sym->line;
		ostypef(sym->buf, buf, sizeof(buf));
		if (stat(buf, &st))
		    parse_error(sym, "%s: %s", buf, strerror(errno));
		strset(&mcx->path, buf);
		sym_get(sym);
		while (sym->line == line) {
		    mcx->argv = realloc(mcx->argv, (mcx->argc + 2) * sizeof(char *));
		    mcx->argv[mcx->argc] = strdup(sym->buf);
		    mcx->argc++;
		    mcx->argv[mcx->argc] = NULL;
		    sym_get(sym);
		}
		if (!mcx->argv[0]) {
		    mcx->argv = realloc(mcx->argv, 2 * sizeof(char *));
		    mcx->argv[0] = strdup(mcx->path);
		    mcx->argv[1] = NULL;
		}
		continue;
	    }
	case S_eof:
	case S_closebra:
	    if (!mcx->argv)
		parse_error(sym, "Missing \"exec\" declaration.");
	    return MAVIS_CONF_OK;
	case S_action:
	    mavis_module_parse_action(mcx, sym);
	    continue;
	default:
	    parse_error_expect(sym, S_script, S_userid, S_groupid, S_home, S_childs, S_setenv, S_exec, S_action, S_closebra, S_unknown);
	}
    }
}

#define HAVE_mavis_drop_in
static void mavis_drop_in(mavis_ctx * mcx)
{
    int i;

    free(mcx->path);

    for (i = 0; mcx->argv[i]; i++)
	Xfree(&mcx->argv[i]);

    for (i = 0; i < mcx->child_max; i++)
	if (mcx->cx[i]) {
	    if (mcx->cx[i]->fd_in > -1)
		io_close(mcx->io, mcx->cx[i]->fd_in);
	    if (mcx->cx[i]->fd_out > -1)
		io_close(mcx->io, mcx->cx[i]->fd_out);
	    if (mcx->cx[i]->fd_err > -1)
		io_close(mcx->io, mcx->cx[i]->fd_err);
	    if (mcx->cx[i]) {
		kill(mcx->cx[i]->pid, SIGTERM);
	    }

	    av_free(mcx->cx[i]->ac);

	    free(mcx->cx[i]);
	}

    RB_tree_delete(mcx->junkcontexts);

    RB_tree_delete(mcx->backlog_app_ctx);
    RB_tree_delete(mcx->backlog_serial);
    RB_tree_delete(mcx->backlog_fifo);
    RB_tree_delete(mcx->outgoing);

    if (mcx->env) {
	for (i = 0; i < mcx->envcount; i++)
	    free(mcx->env[i]);
	free(mcx->env);
    }

    free(mcx->cx);
    free(mcx->cx_stat);

    io_destroy(mcx->io_context_local, NULL);
}

static void child_closed_stderr(struct context *ctx, int cur __attribute__((unused)))
{
    if (ctx->b_err_len) {
	logmsg("%s: %lu: %s", ctx->mcx->argv[0], (u_long) ctx->pid, ctx->b_err);
	ctx->b_err_len = 0;
    }
    RB_search_and_delete(ctx->mcx->junkcontexts, ctx);
}

static void write_to_child(struct context *, int);
static void start_query(struct context *);
static int mavis_send_in(mavis_ctx *, av_ctx **);

static void child_died(struct context *ctx, int cur __attribute__((unused)))
{
    if (ctx->ac) {		// might be called multiple times else
	int i = ctx->index;
	DebugIn(DEBUG_PROC);

	if (ctx->mcx->cx[i]->counter < 2) {
	    logmsg("%s: %lu: terminated before finishing first request", ctx->mcx->argv[0], (u_long) ctx->pid);
	    ctx->mcx->reaphist[ctx->mcx->reapcur] = io_now.tv_sec + REAPINT;
	    ctx->mcx->reapcur++;
	    ctx->mcx->reapcur %= REAPMAX;
	    ctx->mcx->usage--;
	} else
	    logmsg("%s: %lu: terminated after processing %llu requests", ctx->mcx->argv[0], (u_long) ctx->pid, ctx->mcx->cx[i]->counter);

	ctx->mcx->cx[i]->counter = 0;

	io_child_set(ctx->pid, NULL, NULL);

	if (ctx->fd_in > -1) {
	    io_close(ctx->mcx->io, ctx->fd_in);
	    ctx->fd_in = -1;
	}
	if (ctx->fd_out > -1) {
	    io_close(ctx->mcx->io, ctx->fd_out);
	    ctx->fd_out = -1;
	}

	ctx->index = -1;

	RB_insert(ctx->mcx->junkcontexts, ctx);

#ifdef DEBUG_RB
	fprintf(stderr, "EXT insert junkcontexts %p\n", ctx);
#endif

	ctx->mcx->cx[i] = NULL;
	ctx->mcx->child_cur--;

	fork_child(ctx->mcx, i);

	if (ctx->mcx->cx[i]) {
	    ctx->mcx->cx[i]->ac = ctx->ac;
	    ctx->ac = NULL;

	    ctx->mcx->cx_stat[i].counter++;
	    ctx->mcx->cx_stat[i].counter_p++;
	    start_query(ctx->mcx->cx[i]);
	}

	DebugOut(DEBUG_PROC);
    }
}

static void read_from_child(struct context *ctx, int cur)
{
    ssize_t len;
    DebugIn(DEBUG_MAVIS);

    len = Read(ctx->fd_in, ctx->b_in + ctx->b_in_len, sizeof(ctx->b_in) - ctx->b_in_len - 1);

    if (len > 0) {
	char *t;
	int matchlevel = 0;

	Debug((DEBUG_PROC, "%s:%d %s\n", __FILE__, __LINE__, ctx->mcx->path));
	ctx->b_in_len += len;
	ctx->b_in[ctx->b_in_len] = 0;

	for (t = ctx->b_in + ctx->b_in_len - 1; t > ctx->b_in; t--)
	    switch (matchlevel) {
	    case 0:
		if (*t != '\n') {
		    DebugOut(DEBUG_MAVIS);
		    return;
		}
		matchlevel++;
		break;
	    case 1:
		if (!isdigit((int) *t)) {
		    DebugOut(DEBUG_MAVIS);
		    return;
		}
		matchlevel++;
		break;
	    case 2:
		if (!isdigit((int) *t) && *t != '-' && *t != '=') {
		    DebugOut(DEBUG_MAVIS);
		    return;
		}
		if (*t == '=')
		    matchlevel++;
		break;
	    case 3:
		if (*t == '\n') {
		    rb_node_t *r;
		    struct query *q;
		    char *serial = av_get(ctx->ac, AV_A_SERIAL);
		    char *serial_old = alloca(strlen(serial) + 1);
		    int result;

		    strcpy(serial_old, serial);

		    io_clr_i(ctx->mcx->io, ctx->fd_in);

		    av_clear(ctx->ac);
		    *++t = 0;
		    av_char_to_array(ctx->ac, ctx->b_in, NULL);
		    result = atoi(++t);

		    ctx->in_use = 0;
		    ctx->mcx->usage--;

		    serial = av_get(ctx->ac, AV_A_SERIAL);

		    if (!serial || strcmp(serial, serial_old)) {
			if (serial)
			    logmsg("%s: %lu: out of sync: " "got %s, expected %s. Terminating.", ctx->mcx->argv[0], (u_long) ctx->pid, serial, serial_old);
			else
			    logmsg("%s: %lu: missing serial. Terminating.", ctx->mcx->argv[0], (u_long) ctx->pid);
			av_free(ctx->ac);
			ctx->ac = NULL;
			kill(ctx->pid, SIGTERM);
			child_died(ctx, ctx->fd_in);
			DebugOut(DEBUG_MAVIS);
			return;
		    }
		    if (result == MAVIS_FINAL) {
			char *r = av_get(ctx->ac, AV_A_RESULT);
			if (r && (!strcmp(r, AV_V_RESULT_OK) || !strcmp(r, AV_V_RESULT_FAIL)))
			    av_set(ctx->ac, AV_A_IDENTITY_SOURCE, ctx->mcx->identity_source_name);
		    }

		    q = Xcalloc(1, sizeof(struct context));
		    q->ac = ctx->ac;
		    ctx->ac = NULL;

		    q->result = result;

		    q->canceled = ctx->canceled;
		    ctx->canceled = 0;

		    RB_insert(ctx->mcx->outgoing, q);
#ifdef DEBUG_RB
		    fprintf(stderr, "EXT insert outgoing %p\n", q);
#endif

		    if (ctx->mcx->io_context_parent) {
			if (!RB_empty(ctx->mcx->backlog_fifo)) {
			    rb_node_t *rbn = RB_first(ctx->mcx->backlog_fifo);
			    struct query *qp = RB_payload(rbn, struct query *);
			    Debug((DEBUG_PROC, "%s:%d\n", __FILE__, __LINE__));
			    RB_search_and_delete(ctx->mcx->backlog_app_ctx, qp);
			    RB_search_and_delete(ctx->mcx->backlog_serial, qp);
			    ctx->ac = qp->ac;
			    qp->ac = NULL;
			    RB_delete(ctx->mcx->backlog_fifo, rbn);
#ifdef DEBUG_RB
			    fprintf(stderr, "EXT remove backlog_fifo %p\n", RB_payload(rbn, void *));
#endif
			    ctx->mcx->backlog_cur--;
			    ctx->mcx->usage++;
			    ctx->mcx->cx_stat[ctx->index].counter++;
			    ctx->mcx->cx_stat[ctx->index].counter_p++;
			    start_query(ctx);
			}

			while ((r = RB_first(ctx->mcx->outgoing))) {
			    struct query *qp = RB_payload(r, struct query *);

			    if (ctx->mcx->ac_bak)
				av_free(ctx->mcx->ac_bak);
			    ctx->mcx->ac_bak = qp->ac_bak;
			    qp->ac_bak = NULL;

			    if (q->canceled) {
				av_free(ctx->mcx->ac_bak);
				ctx->mcx->ac_bak = NULL;
				RB_delete(ctx->mcx->outgoing, r);
			    } else
				((void (*)(void *)) qp->ac->app_cb) (qp->ac->app_ctx);
			}
		    }
		    DebugOut(DEBUG_MAVIS);
		    return;
		}
	    }
    } else			//if(errno != EAGAIN)
	child_died(ctx, cur);
    DebugOut(DEBUG_MAVIS);
}

static void write_to_child(struct context *ctx, int cur)
{
    ssize_t len;
    DebugIn(DEBUG_PROC);

    len = Write(ctx->fd_out, ctx->b_out + ctx->b_out_off, ctx->b_out_len - ctx->b_out_off);

    if (len > 0) {
	ctx->b_out_off += len;
	if (ctx->b_out_len == ctx->b_out_off) {
	    io_clr_o(ctx->mcx->io, ctx->fd_out);
	    io_set_i(ctx->mcx->io, ctx->fd_in);
	} else
	    io_set_o(ctx->mcx->io, ctx->fd_out);
    } else			//if(errno != EAGAIN)
	child_died(ctx, cur);

    DebugOut(DEBUG_PROC);
}

static void read_err_from_child(struct context *ctx, int cur __attribute__((unused)))
{
    ssize_t len;

    DebugIn(DEBUG_PROC);

    len = Read(ctx->fd_err, ctx->b_err + ctx->b_err_len, sizeof(ctx->b_err) - ctx->b_err_len - 1);

    Debug((DEBUG_PROC, " fd %d: read %d bytes (errno: %d, pid: %d\n", cur, (int) len, errno, (int) ctx->pid));

    Debug((DEBUG_ALL, ">>>%.*s<<<\n", (int) len, ctx->b_err + ctx->b_err_len));

    if (len > 0) {
	char *linestart = ctx->b_err;
	char *lineend;

	ctx->b_err_len += len;
	ctx->b_err[ctx->b_err_len] = 0;

	while ((lineend = strchr(linestart, '\n'))) {
	    *lineend = 0;
	    logmsg("%s: %lu: %s", ctx->mcx->argv[0], (u_long) ctx->pid, linestart);
	    linestart = lineend + 1;
	}

	ctx->b_err_off = linestart - ctx->b_err;
	if (ctx->b_err_off)
	    memmove(ctx->b_err, linestart, ctx->b_err_len - ctx->b_err_off + 1);
	ctx->b_err_len -= ctx->b_err_off;
	ctx->b_err_off = 0;
    } else			//if (errno != EAGAIN)
	child_closed_stderr(ctx, cur);

    DebugOut(DEBUG_PROC);
}

static int fork_child(mavis_ctx * mcx, int i)
{
    int fi[2], fo[2], fe[2];
    pid_t childpid;

    if (mcx->reaphist[mcx->reapcur] >= io_now.tv_sec) {
	logmsg("%s: %s respawning too fast; throttling for %ld seconds.", MAVIS_name, mcx->path, (u_long) (mcx->reaphist[mcx->reapcur] - io_now.tv_sec));
	return -1;
    }

    Debug((DEBUG_PROC, "forking child number %d\n", i));

    signal(SIGPIPE, SIG_IGN);

    if (pipe(fi) < 0) {
	logerr("pipe (%s:%d)", __FILE__, __LINE__);
	return -1;
    }
    if (pipe(fo) < 0) {
	logerr("pipe (%s:%d)", __FILE__, __LINE__);
	close(fi[0]);
	close(fi[1]);
	return -1;
    }
    if (pipe(fe) < 0) {
	logerr("pipe (%s:%d)", __FILE__, __LINE__);
	close(fi[0]);
	close(fi[1]);
	close(fo[0]);
	close(fo[1]);
	return -1;
    }
#ifdef DEBUG
    fflush(stderr);
#endif

    switch ((childpid = io_child_fork(NULL, NULL))) {
    case 0:
	signal(SIGCHLD, SIG_DFL);
	close(fi[1]);
	close(fo[0]);
	close(fe[0]);
	dup2(fi[0], 0);
	dup2(fo[1], 1);
	dup2(fe[1], 2);
	if (mcx->home && chdir(mcx->home)) {
	    logerr("chdir(%s) (%s:%d)", mcx->home, __FILE__, __LINE__);
	    //FIXME
	}
	if (mcx->gid)
	    UNUSED_RESULT(setgid(mcx->gid));
	if (mcx->uid)
	    UNUSED_RESULT(setuid(mcx->uid));

	if (mcx->env)
	    execve(mcx->path, mcx->argv, mcx->env);
	else
	    execv(mcx->path, mcx->argv);

	logerr("exec (%s) (%s:%d)", mcx->path, __FILE__, __LINE__);
	exit(0);
    case -1:
	logerr("fork (%s:%d)", __FILE__, __LINE__);
	close(fi[0]);
	close(fo[0]);
	close(fe[0]);
	close(fi[1]);
	close(fo[1]);
	close(fe[1]);
	return -1;
    }
    signal(SIGCHLD, SIG_IGN);

    close(fi[0]);
    close(fo[1]);
    close(fe[1]);

#ifdef SO_NOSIGPIPE
    {
	int one = 1;
	setsockopt(fi[1], SOL_SOCKET, SO_NOSIGPIPE, (const char *) &one, sizeof(one));
	setsockopt(fo[0], SOL_SOCKET, SO_NOSIGPIPE, (const char *) &one, sizeof(one));
	setsockopt(fe[0], SOL_SOCKET, SO_NOSIGPIPE, (const char *) &one, sizeof(one));
    }
#endif

    fcntl(fi[1], F_SETFD, FD_CLOEXEC);
    fcntl(fo[0], F_SETFD, FD_CLOEXEC);
    fcntl(fe[0], F_SETFD, FD_CLOEXEC);

    fcntl(fi[1], F_SETFL, O_NONBLOCK);
    fcntl(fo[0], F_SETFL, O_NONBLOCK);
    fcntl(fe[0], F_SETFL, O_NONBLOCK);

    mcx->cx[i] = Xcalloc(1, sizeof(struct context));
    mcx->cx[i]->mcx = mcx;
    mcx->cx[i]->index = i;
    mcx->cx[i]->pid = childpid;
    mcx->cx[i]->fd_out = fi[1];
    mcx->cx[i]->fd_in = fo[0];
    mcx->cx[i]->fd_err = fe[0];

    mcx->child_cur++;

    io_register(mcx->io, mcx->cx[i]->fd_out, mcx->cx[i]);
    io_set_cb_o(mcx->io, mcx->cx[i]->fd_out, (void *) write_to_child);
    io_clr_cb_i(mcx->io, mcx->cx[i]->fd_out);
    io_set_cb_h(mcx->io, mcx->cx[i]->fd_out, (void *) child_died);
    io_set_cb_e(mcx->io, mcx->cx[i]->fd_out, (void *) child_died);

    io_register(mcx->io, mcx->cx[i]->fd_in, mcx->cx[i]);
    io_clr_cb_o(mcx->io, mcx->cx[i]->fd_in);
    io_set_cb_i(mcx->io, mcx->cx[i]->fd_in, (void *) read_from_child);
    io_set_cb_h(mcx->io, mcx->cx[i]->fd_in, (void *) child_died);
    io_set_cb_e(mcx->io, mcx->cx[i]->fd_in, (void *) child_died);

    io_register(mcx->io, mcx->cx[i]->fd_err, mcx->cx[i]);
    io_clr_cb_o(mcx->io, mcx->cx[i]->fd_err);
    io_set_cb_i(mcx->io, mcx->cx[i]->fd_err, (void *) read_err_from_child);
    io_set_cb_h(mcx->io, mcx->cx[i]->fd_err, (void *) child_closed_stderr);
    io_set_cb_e(mcx->io, mcx->cx[i]->fd_err, (void *) child_closed_stderr);
    io_set_i(mcx->io, mcx->cx[i]->fd_err);
    mcx->cx_stat[i].startup++;
    mcx->cx_stat[i].startup_p++;

    return 0;
}

static void start_query(struct context *ctx)
{

    if (ctx) {
	int l;

	Debug((DEBUG_PROC, "starting query on child %d (%s)\n", ctx->index, av_get(ctx->ac, AV_A_SERIAL)));
	ctx->in_use = 1;

	ctx->b_in_len = ctx->b_in_off = ctx->b_out_len = ctx->b_out_off = 0;
	l = av_array_to_char(ctx->ac, ctx->b_out, sizeof(ctx->b_out) - 3, NULL);
	if (l > -1) {
	    strcpy(ctx->b_out + l, "=\n");
	    ctx->b_out_len = l + 2;
	    write_to_child(ctx, ctx->fd_out);
	} else
	    logmsg("%s: query too long, ignoring", MAVIS_name);
    }
}

#define HAVE_mavis_send_in
static int mavis_send_in(mavis_ctx * mcx, av_ctx ** ac)
{
    int i = -1;
    int res = MAVIS_DEFERRED;

    if (!strcasecmp(av_get(*ac, AV_A_TYPE), AV_V_TYPE_LOGSTATS)) {
	unsigned long long counter = 0;
	unsigned long long counter_p = 0;
	u_long startup = 0;
	u_long startup_p = 0;

	for (i = 0; i < mcx->child_max; i++)
	    if (mcx->cx[i]) {
		logmsg("STAT %s: %d: Q=%llu F=%lu q=%llu f=%lu",
		       MAVIS_name, i, mcx->cx_stat[i].counter, mcx->cx_stat[i].startup, mcx->cx_stat[i].counter_p, mcx->cx_stat[i].startup_p);

		counter += mcx->cx_stat[i].counter;
		counter_p += mcx->cx_stat[i].counter_p;
		startup += mcx->cx_stat[i].startup;
		startup_p += mcx->cx_stat[i].startup_p;
		mcx->cx_stat[i].counter_p = 0;
		mcx->cx_stat[i].startup_p = 0;
	    }

	logmsg
	    ("STAT %s: Q=%llu F=%lu B=%lu T=%d q=%llu f=%lu b=%lu t=%d",
	     MAVIS_name, counter, startup, mcx->backlog_max,
	     (int) (io_now.tv_sec - mcx->startup_time), counter_p, startup_p, mcx->backlog_max_p, (int) (io_now.tv_sec - mcx->lastdump));

	mcx->backlog_max_p = mcx->backlog_cur;
	mcx->lastdump = io_now.tv_sec;

	res = MAVIS_DOWN;
    } else if (mcx->usage == mcx->child_max) {
	struct query *q = Xcalloc(1, sizeof(struct query));
	char *serial = av_get(*ac, AV_A_SERIAL);
	q->mcx = mcx;
	q->ac = *ac;
	*ac = NULL;

	q->ac_bak = mcx->ac_bak;
	mcx->ac_bak = NULL;

	q->serial_crc = crc32_update(INITCRC32, (u_char *) serial, strlen(serial));
	q->when = io_now.tv_sec;
	q->counter = mcx->counter++;

	RB_insert(mcx->backlog_fifo, q);
#ifdef DEBUG_RB
	fprintf(stderr, "EXT insert backlog_fifo %p\n", q);
#endif
	RB_insert(mcx->backlog_app_ctx, q);
#ifdef DEBUG_RB
	fprintf(stderr, "EXT insert backlog_app_ctx %p\n", q);
#endif
	RB_insert(mcx->backlog_serial, q);
#ifdef DEBUG_RB
	fprintf(stderr, "EXT insert backlog_serial %p\n", q);
#endif

	mcx->backlog_cur++;
	if (mcx->backlog_cur > mcx->backlog_max)
	    mcx->backlog_max = mcx->backlog_cur;
	if (mcx->backlog_cur > mcx->backlog_max_p)
	    mcx->backlog_max_p = mcx->backlog_cur;
    } else {
	/* First, look for active childs that are idle */
	for (i = 0; i < mcx->child_max && (!mcx->cx[i] || mcx->cx[i]->in_use); i++);

	/* If none found: fork a new child process */
	if (i == mcx->child_max) {
	    for (i = 0; i < mcx->child_max && mcx->cx[i]; i++);
	    if (0 > fork_child(mcx, i))
		return MAVIS_IGNORE;
	}

	mcx->cx[i]->ac = *ac;
	*ac = NULL;

	mcx->usage++;
	mcx->cx[i]->counter++;
	mcx->cx_stat[i].counter++;
	mcx->cx_stat[i].counter_p++;
	start_query(mcx->cx[i]);

	if (!mcx->io_context_parent) {
	    rb_node_t *r;

	    while (mcx->cx[i] && mcx->cx[i]->in_use)
		io_poll(mcx->io, -1);

	    r = RB_first(mcx->outgoing);
	    if (r) {
		struct query *q = RB_payload(r, struct query *);
		*ac = q->ac;
		q->ac = NULL;
		res = q->result;
		RB_delete(mcx->outgoing, r);
#ifdef DEBUG_RB
		fprintf(stderr, "EXT delete outgoing %p\n", r);
#endif
	    } else
		res = MAVIS_IGNORE;
	}
    }
    return res;
}

#define HAVE_mavis_cancel_in
static int mavis_cancel_in(mavis_ctx * mcx, void *app_ctx)
{
    struct query q;
    rb_node_t *r;
    int res = MAVIS_DOWN;
    int i;

    q.ac = av_new(NULL, app_ctx);

    if ((r = RB_search(mcx->backlog_app_ctx, &q))) {
	struct query *qp = RB_payload(r, struct query *);
	io_sched_pop(mcx->io, qp);
	mcx->backlog_cur--;
	RB_search_and_delete(mcx->backlog_app_ctx, qp);
	RB_search_and_delete(mcx->backlog_fifo, qp);
	RB_delete(mcx->backlog_serial, r);
#ifdef DEBUG_RB
	fprintf(stderr, "EXT delete backlog_serial %p\n", r);
#endif
    } else if ((r = RB_search(mcx->outgoing, &q))) {
	struct query *qp = RB_payload(r, struct query *);
	io_sched_pop(mcx->io, qp);
	RB_delete(mcx->outgoing, r);
#ifdef DEBUG_RB
	fprintf(stderr, "EXT delete outgoing %p\n", r);
#endif
	res = MAVIS_FINAL;
    }

    for (i = 0; i < mcx->child_max; i++)
	if (mcx->cx[i] && mcx->cx[i]->ac && mcx->cx[i]->ac->app_ctx == app_ctx) {
	    mcx->cx[i]->canceled = 1;
	    break;
	}

    av_free(q.ac);
    return res;
}

#define HAVE_mavis_recv_in
static int mavis_recv_in(mavis_ctx * mcx, av_ctx ** ac, void *app_ctx)
{
    struct query q;
    rb_node_t *r;
    int res = MAVIS_DOWN;

    DebugIn(DEBUG_MAVIS);

    q.ac = av_new(NULL, app_ctx);
    r = RB_search(mcx->outgoing, &q);
    av_free(q.ac);

    if (r) {
	struct query *qp = RB_payload(r, struct query *);
	res = qp->result;
	mcx->last_result = res;
	*ac = qp->ac;
	av_set(*ac, AV_A_CURRENT_MODULE, mcx->identifier);
	qp->ac = NULL;
#ifdef DEBUG_RB
	fprintf(stderr, "EXT delete outgoing %p\n", r);
#endif
	RB_delete(mcx->outgoing, r);
	res = mavis_send(mcx->top, ac);
	if (res == MAVIS_FINAL)
	    res = MAVIS_FINAL_DEFERRED;
    }

    DebugOut(DEBUG_MAVIS);
    return res;
}

#define HAVE_mavis_new
static void mavis_new(mavis_ctx * mcx)
{
    if (mcx->io)
	mcx->child_min = 4, mcx->child_max = 20;
    else
	mcx->child_min = 1, mcx->child_max = 1;
    mcx->io_context_parent = mcx->io;
}

#include "mavis_glue.c"
