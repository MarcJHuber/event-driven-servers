/*
 * libmavis_external-mt.c
 *
 * Backend module for multi-threaded backend scripts.
 * (C)2001-2023 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 * 
 * $Id$
 */

#define MAVIS_name "external-mt"

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

#define REAPMAX 30		/* terminated ctx history table size */
#define REAPINT 30		/* terminated ctx interval (seconds) */

#define MAVIS_CTX_PRIVATE			\
  struct io_context *io_context_local;		\
  struct io_context *io_context_parent;		\
  char *path;					\
  char **argv;					\
  int argc;					\
  struct context *ctx;				\
  rb_tree_t *by_serial;				\
  rb_tree_t *by_app_ctx;			\
  int envcount;					\
  char **env;					\
  int reapcur;					\
  time_t reaphist[REAPMAX];

#include "mavis.h"

struct iobuf {
    char *buf;
    size_t len;
    size_t off;
    struct iobuf *next;
};

struct context {
    mavis_ctx *mcx;
    pid_t pid;
    char b_err[8192];
    size_t hdr_len;
    struct mavis_ext_hdr_v1 hdr;
    size_t b_in_want;
    size_t b_in_got;
    size_t b_err_len;
    size_t b_err_off;
    struct iobuf *b_in;
    struct iobuf *b_out;
    struct iobuf *b_out_last;
    int fd_in;
    int fd_out;
    int fd_err;
    int result;
    unsigned long long counter;
};

static int fork_ctx(mavis_ctx *);

struct query {
    mavis_ctx *mcx;
    av_ctx *ac;
    char *serial;
    uint32_t serial_crc;
    u_int canceled:1;
    int result;
};

static int compare_serial(const void *v1, const void *v2)
{
    if (((struct query *) v1)->serial_crc < ((struct query *) v2)->serial_crc)
	return -1;
    if (((struct query *) v1)->serial_crc > ((struct query *) v2)->serial_crc)
	return +1;
    return strcmp(((struct query *) v1)->serial, ((struct query *) v2)->serial);
}

static int compare_app_ctx(const void *v1, const void *v2)
{
    if (((struct query *) v1)->ac->app_ctx < ((struct query *) v2)->ac->app_ctx)
	return -1;
    if (((struct query *) v1)->ac->app_ctx > ((struct query *) v2)->ac->app_ctx)
	return +1;
    return 0;
}

static void write_to_child(struct context *, int);

#define HAVE_mavis_init_in
static int mavis_init_in(mavis_ctx * mcx)
{
    DebugIn(DEBUG_MAVIS);

    if (!mcx->path)
	logmsg("Warning: %s: module lacks path definition", MAVIS_name);
    else if (!mcx->argv[0]) {
	mcx->argv[0] = Xstrdup(basename(mcx->path));
	mcx->argv[1] = NULL;
    }

    if (!mcx->io_context_parent)
	mcx->io_context_local = mcx->io = io_init();
    mcx->by_serial = RB_tree_new(compare_serial, NULL);
    mcx->by_app_ctx = RB_tree_new(compare_app_ctx, NULL);
    fork_ctx(mcx);
    DebugOut(DEBUG_MAVIS);
    return MAVIS_INIT_OK;
}

/*
exec = path argv0 argv1 argv2...
setenv a = b
*/
#define HAVE_mavis_parse_in
static int mavis_parse_in(mavis_ctx * mcx, struct sym *sym)
{
    char *env_name;
    size_t len;
    struct stat st;

    while (1) {
	switch (sym->code) {
	case S_script:
	    mavis_script_parse(mcx, sym);
	    continue;
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
		ostypef(sym->buf, buf, sizeof(buf));
		if (stat(buf, &st))
		    parse_error(sym, "%s: %s", buf, strerror(errno));
		strset(&mcx->path, buf);
		sym_get(sym);
		while (sym->code == S_string) {
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
	    parse_error_expect(sym, S_script, S_setenv, S_exec, S_action, S_closebra, S_unknown);
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
    Xfree(&mcx->argv);

    if (mcx->ctx) {
	if (mcx->ctx->fd_in > -1)
	    io_close(mcx->io, mcx->ctx->fd_in);
	if (mcx->ctx->fd_out > -1)
	    io_close(mcx->io, mcx->ctx->fd_out);
	if (mcx->ctx->fd_err > -1)
	    io_close(mcx->io, mcx->ctx->fd_err);
	if (mcx->ctx) {
	    kill(mcx->ctx->pid, SIGTERM);
	}

	if (mcx->ctx->b_in)
	    free(mcx->ctx->b_in);
	while (mcx->ctx->b_out) {
	    struct iobuf *next = mcx->ctx->b_out->next;
	    free(mcx->ctx->b_out->buf);
	    free(mcx->ctx->b_out);
	    mcx->ctx->b_out = next;
	}
	free(mcx->ctx);
	mcx->ctx = NULL;
    }

    if (mcx->env) {
	for (i = 0; i < mcx->envcount; i++)
	    Xfree(&mcx->env[i]);
	Xfree(&mcx->env);
    }


    io_destroy(mcx->io_context_local, NULL);
}

static void ctx_closed_stderr(struct context *ctx, int cur __attribute__((unused)))
{
    if (ctx->b_err_len) {
	logmsg("%s: %lu: %s", ctx->mcx->argv[0], (u_long) ctx->pid, ctx->b_err);
	ctx->b_err_len = 0;
    }
    if (ctx->fd_err > -1)
	io_close(ctx->mcx->io, ctx->fd_err);
    ctx->fd_err = -1;
}

static void write_to_child(struct context *, int);
static void start_query(struct context *, av_ctx *);
static int mavis_send_in(mavis_ctx *, av_ctx **);

static void child_died(struct context *ctx, int cur __attribute__((unused)))
{
    if (ctx->fd_in > -1) {
	DebugIn(DEBUG_PROC);

	if (ctx->counter < 2) {
	    logmsg("%s: %lu: terminated before finishing first request", ctx->mcx->argv[0], (u_long) ctx->pid);
	    ctx->mcx->reaphist[ctx->mcx->reapcur] = io_now.tv_sec + REAPINT;
	    ctx->mcx->reapcur++;
	    ctx->mcx->reapcur %= REAPMAX;
	} else {
	    logmsg("%s: %lu: terminated after processing %llu requests", ctx->mcx->argv[0], (u_long) ctx->pid, ctx->counter);
	}

	ctx->counter = 0;

	io_child_set(ctx->pid, NULL, NULL);

	if (ctx->fd_in > -1) {
	    io_close(ctx->mcx->io, ctx->fd_in);
	    ctx->fd_in = -1;
	}
	if (ctx->fd_out > -1) {
	    io_close(ctx->mcx->io, ctx->fd_out);
	    ctx->fd_out = -1;
	}

	if (ctx->fd_err > -1) {
	    io_close(ctx->mcx->io, ctx->fd_err);
	    ctx->fd_err = -1;
	}

	fork_ctx(ctx->mcx);

	if (!RB_empty(ctx->mcx->by_serial)) {
	    rb_node_t *rbn;

	    for (rbn = RB_first(ctx->mcx->by_serial); rbn;) {
		struct query *q = RB_payload(rbn, struct query *);
		rb_node_t *next = RB_next(rbn);
		if (q->canceled) {
		    RB_delete(ctx->mcx->by_serial, rbn);
		    RB_delete(ctx->mcx->by_app_ctx, rbn);
		    free(q->ac);
		    free(q);
		} else
		    start_query(ctx, q->ac);
		rbn = next;
	    }
	}

	DebugOut(DEBUG_PROC);
    }
}


// assuption here is that the ctx's answer can be fully read and
// we don't need to care for blocking read() calls
static void read_from_child(struct context *ctx, int cur __attribute__((unused)))
{
    int len = 0;
    DebugIn(DEBUG_MAVIS);

    if (ctx->hdr_len < sizeof(struct mavis_ext_hdr_v1)) {
	len = Read(ctx->fd_in, (char *) &ctx->hdr + ctx->hdr_len, sizeof(struct mavis_ext_hdr_v1) - ctx->hdr_len);
	if (len < 0) {
	  read_error:
	    logmsg("%s: %lu: read error. Terminating ctx.", ctx->mcx->argv[0], (u_long) ctx->pid);
	    kill(ctx->pid, SIGTERM);
	    child_died(ctx, ctx->fd_in);
	    DebugOut(DEBUG_MAVIS);
	    return;
	}
	ctx->hdr_len += len;
	if (ctx->hdr_len != sizeof(struct mavis_ext_hdr_v1)) {
	    DebugOut(DEBUG_MAVIS);
	    return;
	}
	if (ntohl(ctx->hdr.magic) != MAVIS_EXT_MAGIC_V1)	// Ma<version>
	    goto read_error;
    }

    size_t hbl = ntohl(ctx->hdr.body_len);
    ctx->b_in = calloc(1, sizeof(struct iobuf));
    ctx->b_in->buf = calloc(1, hbl + 1);
    if (ctx->b_in->len < ctx->hdr.body_len) {
	len = Read(ctx->fd_in, ctx->b_in->buf + ctx->b_in->len, hbl - ctx->b_in->len);
	if (len < 0)
	    goto bye;
	ctx->b_in->len += len;
	if (ctx->b_in->len < hbl) {
	    DebugOut(DEBUG_MAVIS);
	    return;
	}
    }
    av_ctx *ac_in = av_new(NULL, NULL);
    av_char_to_array(ac_in, ctx->b_in->buf, NULL);
    struct query q_tmp;
    q_tmp.serial = av_get(ac_in, AV_A_SERIAL);
    q_tmp.serial_crc = crc32_update(INITCRC32, (u_char *) q_tmp.serial, strlen(q_tmp.serial));
    rb_node_t *rbn = RB_search(ctx->mcx->by_serial, &q_tmp);
    if (!rbn) {
	fprintf(stderr, "Request not found\n");
	av_free(ac_in);
	goto bye;
    }
    struct query *q = RB_payload(rbn, struct query *);
    ac_in->app_ctx = q->ac->app_ctx;
    ac_in->app_cb = q->ac->app_cb;
    av_free(q->ac);
    q->ac = ac_in;
    q->result = ntohl(ctx->hdr.result);

    if (q->result == MAVIS_FINAL) {
	char *r = av_get(ac_in, AV_A_RESULT);
	if (r && (!strcmp(r, AV_V_RESULT_OK) || !strcmp(r, AV_V_RESULT_FAIL)))
	    av_set(ac_in, AV_A_IDENTITY_SOURCE, ctx->mcx->identity_source_name);
    }

    if (!q->canceled)
	((void (*)(void *)) q->ac->app_cb) (q->ac->app_ctx);

#if 0				// mavis_recv_in will do this
    RB_search_and_delete(ctx->mcx->by_serial, q);
    RB_search_and_delete(ctx->mcx->by_app_ctx, q);
    av_free(q->ac);
    free(q);
#endif

  bye:
    ctx->hdr_len = 0;
    free(ctx->b_in->buf);
    free(ctx->b_in);
    ctx->b_in = NULL;
    DebugOut(DEBUG_MAVIS);
}

static void write_to_child(struct context *ctx, int cur)
{
    ssize_t len = -1;

    DebugIn(DEBUG_PROC);

    if (ctx->b_out)
	len = Write(ctx->fd_out, ctx->b_out->buf + ctx->b_out->off, ctx->b_out->len - ctx->b_out->off);

    if (len > 0) {
	ctx->b_out->off += len;
	if (ctx->b_out->len == ctx->b_out->off) {
	    struct iobuf *next = ctx->b_out->next;
	    free(ctx->b_out->buf);
	    free(ctx->b_out);
	    ctx->b_out = next;
	    if (!ctx->b_out)
		io_clr_o(ctx->mcx->io, ctx->fd_out);
	    io_set_i(ctx->mcx->io, ctx->fd_in);
	}
	DebugOut(DEBUG_PROC);
	return;
    }
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
	ctx_closed_stderr(ctx, cur);

    DebugOut(DEBUG_PROC);
}

static int fork_ctx(mavis_ctx * mcx)
{
    int fi[2], fo[2], fe[2];
    pid_t ctxpid;

    if (mcx->reaphist[mcx->reapcur] >= io_now.tv_sec) {
	logmsg("%s: %s respawning too fast; throttling for %ld seconds.", MAVIS_name, mcx->path, (u_long) (mcx->reaphist[mcx->reapcur] - io_now.tv_sec));
	return -1;
    }

    Debug((DEBUG_PROC, "forking ctx\n"));

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

    switch ((ctxpid = io_child_fork(NULL, NULL))) {
    case 0:
	signal(SIGCHLD, SIG_DFL);
	close(fi[1]);
	close(fo[0]);
	close(fe[0]);
	dup2(fi[0], 0);
	dup2(fo[1], 1);
	dup2(fe[1], 2);
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

    if (!mcx->ctx)
	mcx->ctx = Xcalloc(1, sizeof(struct context));
    mcx->ctx->mcx = mcx;
    mcx->ctx->pid = ctxpid;
    mcx->ctx->fd_out = fi[1];
    mcx->ctx->fd_in = fo[0];
    mcx->ctx->fd_err = fe[0];

    io_register(mcx->io, mcx->ctx->fd_out, mcx->ctx);
    io_set_cb_o(mcx->io, mcx->ctx->fd_out, (void *) write_to_child);
    io_clr_cb_i(mcx->io, mcx->ctx->fd_out);
    io_set_cb_h(mcx->io, mcx->ctx->fd_out, (void *) child_died);
    io_set_cb_e(mcx->io, mcx->ctx->fd_out, (void *) child_died);

    io_register(mcx->io, mcx->ctx->fd_in, mcx->ctx);
    io_clr_cb_o(mcx->io, mcx->ctx->fd_in);
    io_set_cb_i(mcx->io, mcx->ctx->fd_in, (void *) read_from_child);
    io_set_cb_h(mcx->io, mcx->ctx->fd_in, (void *) child_died);
    io_set_cb_e(mcx->io, mcx->ctx->fd_in, (void *) child_died);
    io_set_i(mcx->io, mcx->ctx->fd_err);

    io_register(mcx->io, mcx->ctx->fd_err, mcx->ctx);
    io_clr_cb_o(mcx->io, mcx->ctx->fd_err);
    io_set_cb_i(mcx->io, mcx->ctx->fd_err, (void *) read_err_from_child);
    io_set_cb_h(mcx->io, mcx->ctx->fd_err, (void *) ctx_closed_stderr);
    io_set_cb_e(mcx->io, mcx->ctx->fd_err, (void *) ctx_closed_stderr);
    io_set_i(mcx->io, mcx->ctx->fd_err);

    return 0;
}

static void start_query(struct context *ctx, av_ctx * ac)
{
    size_t len = av_array_to_char_len(ac);
    struct iobuf *o = calloc(1, sizeof(struct iobuf));
    o->buf = calloc(1, len + sizeof(struct mavis_ext_hdr_v1));

    Debug((DEBUG_PROC, "starting query (%s)\n", av_get(ac, AV_A_SERIAL)));

    o->len = av_array_to_char(ac, o->buf + sizeof(struct mavis_ext_hdr_v1), len, NULL);
    struct mavis_ext_hdr_v1 *hdr = (struct mavis_ext_hdr_v1 *) o->buf;
    hdr->magic = htonl(MAVIS_EXT_MAGIC_V1);
    hdr->body_len = htonl((uint32_t) o->len);
    o->len += sizeof(struct mavis_ext_hdr_v1);
    if (ctx->b_out) {
	ctx->b_out_last->next = o;
	ctx->b_out_last = o;
    } else {
	ctx->b_out = o;
	ctx->b_out_last = o;
	io_set_o(ctx->mcx->io, ctx->fd_out);
    }
}

#define HAVE_mavis_send_in
static int mavis_send_in(mavis_ctx * mcx, av_ctx ** ac)
{
    int res = MAVIS_DEFERRED;
    struct query *q = calloc(1, sizeof(struct query));
    q->serial = av_get(*ac, AV_A_SERIAL);
    if (!q->serial) {
	free(q);
	av_set(*ac, AV_A_RESULT, AV_V_RESULT_ERROR);
	return MAVIS_FINAL;
    }
    q->serial_crc = crc32_update(INITCRC32, (u_char *) q->serial, strlen(q->serial));
    q->ac = *ac;

    RB_insert(mcx->by_serial, q);
    RB_insert(mcx->by_app_ctx, q);
    start_query(mcx->ctx, *ac);
    *ac = NULL;

    if (!mcx->io_context_parent) {	// this if for mavistest, actually.
	while (!RB_empty(mcx->by_serial)) {
	    fprintf(stderr, "%s %d\n", __func__, __LINE__);
	    io_poll(mcx->io, -1);
	}
    }
    return res;
}

#define HAVE_mavis_cancel_in
static int mavis_cancel_in(mavis_ctx * mcx, void *app_ctx)
{
    struct query q;
    rb_node_t *rbn;
    int res = MAVIS_DOWN;

    q.ac = av_new(NULL, app_ctx);
    if ((rbn = RB_search(mcx->by_app_ctx, &q))) {
	RB_payload(rbn, struct query *)->canceled = 1;
	res = MAVIS_FINAL;
    }
    av_free(q.ac);
    return res;
}

#define HAVE_mavis_recv_in
static int mavis_recv_in(mavis_ctx * mcx, av_ctx ** ac, void *app_ctx)
{
    struct query q;
    rb_node_t *ra;
    int res = MAVIS_DOWN;

    DebugIn(DEBUG_MAVIS);

    q.ac = av_new(NULL, app_ctx);
    ra = RB_search(mcx->by_app_ctx, &q);
    av_free(q.ac);

    if (ra) {
	struct query *qp = RB_payload(ra, struct query *);
	rb_node_t *rs = RB_search(mcx->by_serial, qp);
	res = qp->result;
	mcx->last_result = res;
	*ac = qp->ac;
	av_set(*ac, AV_A_CURRENT_MODULE, mcx->identifier);
	RB_delete(mcx->by_app_ctx, ra);
	RB_delete(mcx->by_serial, rs);
	res = mavis_send(mcx->top, ac);
	if (res == MAVIS_FINAL)
	    res = MAVIS_FINAL_DEFERRED;
	free(qp);
    }

    DebugOut(DEBUG_MAVIS);
    return res;
}

#define HAVE_mavis_new
static void mavis_new(mavis_ctx * mcx)
{
    mcx->io_context_parent = mcx->io;
}

#include "mavis_glue.c"
