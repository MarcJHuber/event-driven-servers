/*
   Copyright (C) 1999-2022 Marc Huber (Marc.Huber@web.de)
   All rights reserved.

   Redistribution and use in source and binary  forms,  with or without
   modification, are permitted provided  that  the following conditions
   are met:

   1. Redistributions of source code  must  retain  the above copyright
      notice, this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions  and  the following disclaimer in
      the  documentation  and/or  other  materials  provided  with  the
      distribution.

   3. The end-user documentation  included with the redistribution,  if
      any, must include the following acknowledgment:

          This product includes software developed by Marc Huber
	  (Marc.Huber@web.de).

      Alternately,  this  acknowledgment  may  appear  in  the software
      itself, if and wherever such third-party acknowledgments normally
      appear.

   THIS SOFTWARE IS  PROVIDED  ``AS IS''  AND  ANY EXPRESSED OR IMPLIED
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
   IN NO EVENT SHALL  ITS  AUTHOR  BE  LIABLE FOR ANY DIRECT, INDIRECT,
   INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
   BUT NOT LIMITED  TO,  PROCUREMENT OF  SUBSTITUTE  GOODS OR SERVICES;
   LOSS OF USE,  DATA,  OR PROFITS;  OR  BUSINESS INTERRUPTION) HOWEVER
   CAUSED AND ON ANY THEORY OF LIABILITY,  WHETHER IN CONTRACT,  STRICT
   LIABILITY,  OR TORT  (INCLUDING NEGLIGENCE OR OTHERWISE)  ARISING IN
   ANY WAY OUT OF THE  USE  OF  THIS  SOFTWARE,  EVEN IF ADVISED OF THE
   POSSIBILITY OF SUCH DAMAGE.
 */

#include "headers.h"
#include "misc/buffer.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

void *mempool_malloc(rb_tree_t * pool, size_t size)
{
    void *p = calloc(1, size ? size : 1);

    if (p) {
	if (pool)
	    RB_insert(pool, p);
	return p;
    }
    report(NULL, LOG_ERR, ~0, "malloc %d failure", (int) size);
    tac_exit(EX_OSERR);
}

void *mempool_realloc(rb_tree_t * pool, void *p, size_t size)
{
    if (p) {
	if (pool) {
	    rb_node_t *rbn = RB_search(pool, p);
	    if (rbn) {
		RB_payload_unlink(rbn);
		RB_delete(pool, rbn);
	    }
	}
	p = realloc(p, size);
	if (p) {
	    if (pool)
		RB_insert(pool, p);
	    return p;
	}
    } else
	return mempool_malloc(pool, size);

    report(NULL, LOG_ERR, ~0, "realloc %d failure", (int) size);
    tac_exit(EX_OSERR);
}

void mempool_free(rb_tree_t * pool, void *ptr)
{
    void **m = ptr;

    if (*m) {
	if (pool) {
	    rb_node_t *rbn = RB_search(pool, *m);
	    if (rbn) {
		RB_delete(pool, rbn);
		*m = NULL;
	    } else
		report(NULL, LOG_DEBUG, ~0, "potential double-free attempt on %p", *m);
	} else
	    free(*m);
    }
}

static int pool_cmp(const void *a, const void *b)
{
    return (a < b) ? -1 : ((a == b) ? 0 : +1);
}

void mempool_destroy(rb_tree_t * pool)
{
    if (pool)
	RB_tree_delete(pool);
}

rb_tree_t *mempool_create(void)
{
    return RB_tree_new(pool_cmp, free);
}

char *mempool_strdup(rb_tree_t * pool, char *p)
{
    char *n = strdup(p);

    if (n) {
	if (pool)
	    RB_insert(pool, n);
	return n;
    }
    report(NULL, LOG_ERR, ~0, "strdup allocation failure");
    tac_exit(EX_OSERR);
}

char *mempool_strndup(rb_tree_t * pool, u_char * p, int len)
{
    char *string;
    int new_len = len;

    /* 
     * Add space for a null terminator if needed. Also, no telling
     * what various mallocs will do when asked for a length of zero.
     */
    if (!len || p[len - 1])
	new_len++;

    string = mempool_malloc(pool, new_len);

    memcpy(string, p, len);
    return string;
}

int tac_exit(int status)
{
    report(NULL, LOG_DEBUG, ~0, "exit status=%d", status);
    exit(status);
}

static void create_dirs(char *path)
{
    char *p = path;
    while ((p = strchr(p + 1, '/'))) {
	*p = 0;
	mkdir(path, config.mask | ((0111) & (config.mask >> 2)));
	*p = '/';
    }
}

static int tac_lock(int lockfd, int locktype)
{
    struct flock flock;

    memset(&flock, 0, sizeof(flock));
    flock.l_type = locktype;
    flock.l_whence = SEEK_SET;
    return fcntl(lockfd, F_SETLK, &flock);
}

#define tac_lockfd(A) tac_lock(A,F_WRLCK)
#define tac_unlockfd(A) tac_lock(A,F_UNLCK)

struct logfile {
    char *dest;			/* log file dest specification */
    char *name;			/* log file specification */
    struct context_logfile *ctx;	/* current log context */
    void (*log_write)(struct logfile *, char *, size_t);
    void (*log_flush)(struct logfile *);
    int syslog_priority;
    int syslog_compliance;
    char *date_dest;
    sockaddr_union syslog_destination;
    int sock;
    time_t last;
    struct log_item *acct;
    struct log_item *access;
    struct log_item *author;
    struct log_item *conn;
    char *syslog_ident;
    char *priority;
    size_t priority_len;
     BISTATE(flag_syslog);
     BISTATE(flag_sync);
     BISTATE(flag_pipe);
     BISTATE(flag_staticpath);
};

static void log_start(struct logfile *, struct context_logfile *);

static void logdied(pid_t pid __attribute__((unused)), struct context_logfile *ctx, int status __attribute__((unused)))
{
    if (ctx) {
	io_close(common_data.io, ctx->fd);
	ctx->lf->ctx = NULL;
	if (ctx->buf) {
	    log_start(ctx->lf, ctx);
	    io_set_o(common_data.io, ctx->fd);
	}
    }
}

static void logdied_handler(struct context_logfile *ctx, int cur __attribute__((unused)))
{
    io_child_ign(ctx->pid);
    logdied(ctx->pid, ctx, 0);
}

static void logwrite_retry(struct context_logfile *ctx, int cur __attribute__((unused)))
{
    io_sched_del(common_data.io, ctx, (void *) logwrite_retry);
    io_set_o(common_data.io, ctx->fd);
}

static void logwrite(struct context_logfile *ctx, int cur)
{
    struct buffer *b = ctx->buf;
    if (b) {
	if (!ctx->lf->flag_pipe && tac_lockfd(cur)) {
	    io_clr_o(common_data.io, cur);
	    io_sched_add(common_data.io, ctx, (void *) logwrite_retry, 1, 0);
	    return;
	}

	if (!ctx->lf->flag_pipe)
	    lseek(cur, 0, SEEK_END);

	while (b) {
	    ssize_t len = write(cur, b->buf + b->offset,
				b->length - b->offset);
	    if (len < 0 && errno == EAGAIN) {
		if (!ctx->lf->flag_pipe)
		    tac_unlockfd(cur);
		io_clr_o(common_data.io, cur);
		io_sched_add(common_data.io, ctx, (void *) logwrite_retry, 1, 0);
		return;
	    }
	    if (len < 0) {
		logdied_handler(ctx, cur);
	    } else {
		off_t o = (off_t) len;
		ctx->buf = buffer_release(ctx->buf, &o);
		if (!ctx->buf && ctx->dying) {
		    if (!ctx->lf->flag_pipe)
			tac_unlockfd(cur);
		    io_clr_o(common_data.io, cur);
		    io_close(common_data.io, cur);
		    ctx->lf->ctx = NULL;
		    free(ctx);
		    return;
		}
	    }
	    b = ctx->buf;
	}

	if (!ctx->lf->flag_pipe)
	    tac_unlockfd(cur);
    }
    io_clr_o(common_data.io, cur);
}

static void logwrite_sync(struct context_logfile *ctx, int cur)
{
    while (ctx->buf) {
	struct iovec v[10];
	int count = 10;
	buffer_setv(ctx->buf, v, &count, buffer_getlen(ctx->buf));
	if (count) {
	    ssize_t l = writev(cur, v, count);
	    off_t o = (off_t) l;
	    if (l < 0) {
		//FIXME. Disk full, probably.
		return;
	    }
	    ctx->buf = buffer_release(ctx->buf, &o);
	}
    }
}

static void log_start(struct logfile *lf, struct context_logfile *deadctx)
{
    char newpath[PATH_MAX + 1];
    char *path = NULL;
    int cur = -1;

    if (deadctx) {
	path = deadctx->path;
    } else if (!lf->flag_syslog) {
	if (lf->flag_staticpath) {
	    path = lf->dest;
	} else {
	    time_t dummy = (time_t) io_now.tv_sec;
	    struct tm *tm = localtime(&dummy);
	    if (!strftime(newpath, sizeof(newpath), lf->dest, tm)) {
		report(NULL, LOG_DEBUG, ~0, "strftime failed for %s", lf->dest);
		return;
	    }
	    path = newpath;
	    if (lf->ctx && strcmp(path, lf->ctx->path)) {
		if (lf->flag_sync) {
		    while (lf->ctx->buf) {
			struct iovec v[10];
			int count = 10;
			size_t len = buffer_getlen(lf->ctx->buf);
			buffer_setv(lf->ctx->buf, v, &count, len);
			if (count) {
			    off_t o = (off_t) len;
			    count = writev(lf->ctx->fd, v, count);
			    lf->ctx->buf = buffer_release(lf->ctx->buf, &o);
			}
		    }
		    close(lf->ctx->fd);
		    free(lf->ctx);
		    lf->ctx = NULL;
		} else {
		    if (lf->ctx->buf == NULL) {
			if (lf->ctx->fd > -1)
			    io_close(common_data.io, lf->ctx->fd);
			free(lf->ctx);
			lf->ctx = NULL;
		    } else {
			lf->ctx->dying = 1;
			lf->ctx = NULL;
		    }
		}
	    }
	}
    }

    if (!lf->ctx) {

	if (lf->last + 5 > io_now.tv_sec) {
	    report(NULL, LOG_INFO, ~0, "\"%s\" respawning too fast", lf->dest);
	    return;
	}

	lf->last = io_now.tv_sec;

	if (lf->flag_pipe) {
	    int fds[2], flags;
	    pid_t pid;

	    if (pipe(fds)) {
		report(NULL, LOG_DEBUG, ~0, "pipe (%s:%d): %s", __FILE__, __LINE__, strerror(errno));
		return;
	    }
	    switch ((pid = io_child_fork((void (*)(pid_t, void *, int)) logdied, deadctx))) {
	    case 0:
		io_destroy(common_data.io, NULL);
		close(fds[1]);
		if (fds[0]) {
		    dup2(fds[0], 0);
		    close(fds[0]);
		}

		/*
		 * Casting NULL to (char *) NULL to avoid GCC warnings
		 * observed on OpenBSD ...
		 */
		execl("/bin/sh", "sh", "-c", path, (char *) NULL);
		execl("/usr/bin/sh", "sh", "-c", path, (char *) NULL);

		report(NULL, LOG_DEBUG, ~0, "execl (%s, ...) (%s:%d)", path, __FILE__, __LINE__);
		exit(EX_OSERR);
	    case -1:
		report(NULL, LOG_DEBUG, ~0, "fork (%s:%d): %s", __FILE__, __LINE__, strerror(errno));
		break;
	    default:
		close(fds[0]);
		flags = fcntl(fds[1], F_GETFD, 0) | FD_CLOEXEC;
		fcntl(fds[1], F_SETFD, flags);
		cur = fds[1];
		if (deadctx)
		    lf->ctx = deadctx;
		else {
		    lf->ctx = calloc(1, sizeof(struct context_logfile));
		    strncpy(lf->ctx->path, path, PATH_MAX);
		    io_child_set(pid, (void (*)(pid_t, void *, int))
				 logdied, (void *) lf->ctx);
		}
		lf->ctx->pid = pid;
	    }
	} else if (lf->flag_syslog) {
	    lf->ctx = calloc(1, sizeof(struct context_logfile));
	    lf->flag_sync = 1;
	    openlog(lf->syslog_ident, 0, lf->syslog_priority / 8);
	} else {
	    cur = open(path, O_CREAT | O_WRONLY | O_APPEND, config.mask);
	    if (cur < 0 && errno != EACCES) {
		create_dirs(path);
		cur = open(path, O_CREAT | O_WRONLY | O_APPEND, config.mask);
	    }
	    if (cur > -1 && !lf->ctx) {
		lf->ctx = calloc(1, sizeof(struct context_logfile));
		strncpy(lf->ctx->path, path, PATH_MAX);
	    }
	}

	if (lf->ctx) {
	    lf->ctx->fd = cur;
	    lf->ctx->lf = lf;

	    if (cur > -1 && !lf->flag_sync) {
		io_register(common_data.io, cur, lf->ctx);
		io_set_cb_h(common_data.io, cur, (void *) logdied_handler);
		io_set_cb_e(common_data.io, cur, (void *) logdied_handler);
		io_set_cb_o(common_data.io, cur, (void *) logwrite);

		fcntl(cur, F_SETFL, O_NONBLOCK);
	    }
	}
    }
}

static void log_write_async(struct logfile *lf, char *buf, size_t len)
{
    if (lf->ctx) {
	if (buffer_getlen(lf->ctx->buf) > 64000)	/* FIXME? */
	    lf->ctx->buf = buffer_free_all(lf->ctx->buf);
	lf->ctx->buf = buffer_write(lf->ctx->buf, buf, len);
	io_set_o(common_data.io, lf->ctx->fd);
    }
}

static void log_write_common(struct logfile *lf, char *buf, size_t len)
{
    if (lf->ctx)
	lf->ctx->buf = buffer_write(lf->ctx->buf, buf, len);
}

static int is_print(char *text, size_t len, size_t *wlen)
{
    /* Returns TRUE for printable one-byte characters and valid
     * UTF-8 multi-byte characters. An alternative would be to
     * use iswprint(3), but I didn't get that to work correctly.
     */
    size_t i;
    *wlen = 0;
    if (len > 0 && ((*text & 0x80) == 0x00)) {
	*wlen = 1;
	return isprint(*text);
    }
    if (len > 1 && (*text & 0xE0) == 0xC0)
	*wlen = 2;
    else if (len > 2 && (*text & 0xF0) == 0xE0)
	*wlen = 3;
    else if (len > 3 && (*text & 0xF8) == 0xF0)
	*wlen = 4;
    else
	return 0;

    for (i = 1; i < *wlen; i++) {
	text++;
	if ((*text & 0xC0) != 0x80)
	    return 0;
    }
    return -1;
}

static void log_flush_async(struct logfile *lf __attribute__((unused)))
{
}

static void log_flush_syslog(struct logfile *lf __attribute__((unused)))
{
    if (lf->ctx && lf->ctx->buf) {
	off_t len = (off_t) buffer_getlen(lf->ctx->buf);
	syslog(lf->syslog_priority, "%.*s", (int) len, lf->ctx->buf->buf + lf->ctx->buf->offset);
	lf->ctx->buf = buffer_release(lf->ctx->buf, &len);
    }
}

static void log_flush_syslog_udp(struct logfile *lf __attribute__((unused)))
{
    if (lf->ctx && lf->ctx->buf) {
	off_t len = (off_t) buffer_getlen(lf->ctx->buf);
	int r;
	if (lf->syslog_destination.sa.sa_family == AF_UNIX)
	    r = send(lf->sock, lf->ctx->buf->buf + lf->ctx->buf->offset, (int) len, 0);
	else
	    r = sendto(lf->sock, lf->ctx->buf->buf + lf->ctx->buf->offset, (int) len, 0, &lf->syslog_destination.sa, su_len(&lf->syslog_destination));
	if (r < 0)
	    report(NULL, LOG_DEBUG, ~0, "send/sendto (%s:%d): %s", __FILE__, __LINE__, strerror(errno));
	lf->ctx->buf = buffer_release(lf->ctx->buf, &len);
    }
}

static void log_flush_sync(struct logfile *lf)
{
    logwrite_sync(lf->ctx, lf->ctx->fd);
}

int logs_flushed(tac_realm * r)
{
    if (r->logdestinations) {
	rb_node_t *rbn;
	for (rbn = RB_first(r->logdestinations); rbn; rbn = RB_next(rbn)) {
	    struct logfile *lf = RB_payload(rbn, struct logfile *);

	    if (!lf->flag_pipe && !lf->flag_sync && lf->ctx && buffer_getlen(lf->ctx->buf))
		return 0;
	}
    }
    if (r->realms) {
	rb_node_t *rbn;
	for (rbn = RB_first(r->realms); rbn; rbn = RB_next(rbn)) {
	    if (!logs_flushed(RB_payload(rbn, tac_realm *)))
		return 0;
	}
    }
    return -1;
}

static int compare_log(const void *a, const void *b)
{
    return strcmp(((struct logfile *) a)->name, ((struct logfile *) b)->name);
}

struct log_item *parse_log_format(struct sym *);

struct log_item *parse_log_format_inline(char *format, char *file, int line)
{
    struct sym sym;
    memset(&sym, 0, sizeof(sym));
    sym.filename = file;
    sym.line = line;
    sym.in = sym.tin = format;
    sym.len = sym.tlen = strlen(sym.in);
    sym_init(&sym);
    return parse_log_format(&sym);
}

void parse_log(struct sym *sym, tac_realm * r)
{
    static struct log_item *access_file = NULL;
    static struct log_item *access_syslog = NULL;
    static struct log_item *access_syslog3 = NULL;
    static struct log_item *author_file = NULL;
    static struct log_item *author_syslog = NULL;
    static struct log_item *author_syslog3 = NULL;
    static struct log_item *acct_file = NULL;
    static struct log_item *acct_syslog = NULL;
    static struct log_item *acct_syslog3 = NULL;
    static struct log_item *conn_file = NULL;
    static struct log_item *conn_syslog = NULL;
    static struct log_item *conn_syslog3 = NULL;

    struct logfile *lf = calloc(1, sizeof(struct logfile));
    if (sym->code == S_equal)
	sym_get(sym);
    lf->name = strdup(sym->buf);
    if (r->logdestinations && RB_search(r->logdestinations, lf))
	parse_error(sym, "log destination '%s' already defined", lf->name);
    lf->dest = "syslog";
    lf->syslog_ident = "tacplus";
    lf->syslog_priority = common_data.syslog_level | common_data.syslog_facility;
    lf->date_dest = "%Y-%m-%d %H:%M:%S %z";
    sym_get(sym);
    parse(sym, S_openbra);
    while (sym->code != S_closebra) {
	switch (sym->code) {
	case S_authentication:
	case S_access:
	    sym_get(sym);
	    parse(sym, S_format);
	    parse(sym, S_equal);
	    lf->access = parse_log_format(sym);
	    continue;
	case S_authorization:
	    sym_get(sym);
	    parse(sym, S_format);
	    parse(sym, S_equal);
	    lf->author = parse_log_format(sym);
	    continue;
	case S_accounting:
	    sym_get(sym);
	    parse(sym, S_format);
	    parse(sym, S_equal);
	    lf->acct = parse_log_format(sym);
	    continue;
	case S_connection:
	    sym_get(sym);
	    parse(sym, S_format);
	    parse(sym, S_equal);
	    lf->conn = parse_log_format(sym);
	    continue;
	case S_destination:
	    sym_get(sym);
	    parse(sym, S_equal);
	    lf->dest = strdup(sym->buf);
	    sym_get(sym);
	    continue;
	case S_syslog:
	    sym_get(sym);
	    switch (sym->code) {
	    case S_facility:
		sym_get(sym);
		parse(sym, S_equal);
		lf->syslog_priority &= 7;
		lf->syslog_priority |= get_syslog_facility(sym->buf);
		sym_get(sym);
		continue;
	    case S_level:
		sym_get(sym);
		parse(sym, S_equal);
		lf->syslog_priority &= ~7;
		lf->syslog_priority |= get_syslog_level(sym->buf);
		sym_get(sym);
		continue;
	    case S_ident:
		sym_get(sym);
		parse(sym, S_equal);
		lf->syslog_ident = strdup(sym->buf);
		sym_get(sym);
		continue;
	    default:
		parse_error_expect(sym, S_facility, S_level, S_ident, S_unknown);
	    }
	default:
	    parse_error_expect(sym, S_destination, S_log, S_syslog, S_access, S_authorization, S_accounting, S_connection, S_unknown);
	}
    }
    sym_get(sym);
    {
	char buf[10];
	lf->priority_len = snprintf(buf, sizeof(buf), "%d", lf->syslog_priority);
	lf->priority = strdup(buf);
    }

    if (!access_file) {
	acct_file =
	    parse_log_format_inline("\"%Y-%m-%d %H:%M:%S %z\t${nas}\t${user}\t${port}\t${nac}\t${accttype}\t${service}\t${cmd}\n\"", __FILE__, __LINE__);
	acct_syslog =
	    parse_log_format_inline("\"<${priority}>%Y-%m-%d %H:%M:%S %z ${hostname} ${nas}|${user}|${port}|${nac}|${accttype}|${service}|${args}\"",
				    __FILE__, __LINE__);
	acct_syslog3 = parse_log_format_inline("\"${nas}|${user}|${port}|${nac}|${accttype}|${service}|${args}\"", __FILE__, __LINE__);

	author_file =
	    parse_log_format_inline("\"%Y-%m-%d %H:%M:%S %z\t${nas}\t${user}\t${port}\t${nac}\t${profile}\t${result}\t${service}\t${cmd}\n\"", __FILE__,
				    __LINE__);
	author_syslog =
	    parse_log_format_inline("\"<${priority}>%Y-%m-%d %H:%M:%S %z ${hostname} ${nas}|${user}|${port}|${nac}|${profile}|${result}|${service}|${cmd}\"",
				    __FILE__, __LINE__);
	author_syslog3 = parse_log_format_inline("\"${nas}|${user}|${port}|${nac}|${profile}|${result}|${service}|${cmd}\"", __FILE__, __LINE__);

	access_file = parse_log_format_inline("\"%Y-%m-%d %H:%M:%S %z\t${nas}\t${user}\t${port}\t${nac}\t${action} ${hint}\n\"", __FILE__, __LINE__);
	access_syslog =
	    parse_log_format_inline("\"<${priority}>%Y-%m-%d %H:%M:%S %z ${hostname} ${nas}|${user}|${port}|${nac}|${action} ${hint}\"", __FILE__, __LINE__);
	access_syslog3 = parse_log_format_inline("\"${nas}|${user}|${port}|${nac}|${action} ${hint}\"", __FILE__, __LINE__);

	conn_file =
	    parse_log_format_inline("\"%Y-%m-%d %H:%M:%S %z\t${accttype}\t${nas}\t${tls-conn-version}\t${tls-peer-cert-issuer}\t${tls-peer-cert-subject}\n\"",
				    __FILE__, __LINE__);
	conn_syslog =
	    parse_log_format_inline
	    ("\"<${priority}>%Y-%m-%d %H:%M:%S %z ${hostname} ${accttype}|${nas}|${tls-conn-version}|${tls-peer-cert-issuer}|${tls-peer-cert-subject}\"",
	     __FILE__, __LINE__);
	conn_syslog3 =
	    parse_log_format_inline("\"${accttype}|${nas}|${tls-conn-version}|${tls-peer-cert-issuer}|${tls-peer-cert-subject}\"", __FILE__, __LINE__);
    }

    switch (lf->dest[0]) {
    case '/':
	if (!lf->acct)
	    lf->acct = acct_file;
	if (!lf->author)
	    lf->author = author_file;
	if (!lf->access)
	    lf->access = access_file;
	if (!lf->conn)
	    lf->conn = conn_file;
	lf->flag_staticpath = (strchr(lf->dest, '%') == NULL);
	lf->flag_pipe = 0;
	lf->flag_sync = 0;
	lf->log_write = &log_write_async;
	lf->log_flush = &log_flush_async;
	break;
    case '>':
	if (!lf->acct)
	    lf->acct = acct_file;
	if (!lf->author)
	    lf->author = author_file;
	if (!lf->access)
	    lf->access = access_file;
	if (!lf->conn)
	    lf->conn = conn_file;
	lf->dest++;
	lf->log_write = &log_write_common;
	lf->log_flush = &log_flush_sync;
	lf->flag_sync = BISTATE_YES;
	break;
    case '|':
	if (!lf->acct)
	    lf->acct = acct_file;
	if (!lf->author)
	    lf->author = author_file;
	if (!lf->access)
	    lf->access = access_file;
	if (!lf->conn)
	    lf->conn = conn_file;
	lf->dest++;
	lf->flag_pipe = BISTATE_YES;
	lf->log_write = &log_write_async;
	lf->log_flush = &log_flush_async;
	break;
    default:
	if (!strcmp(lf->dest, codestring[S_syslog])) {
	    if (!lf->acct)
		lf->acct = acct_syslog3;
	    if (!lf->author)
		lf->author = author_syslog3;
	    if (!lf->access)
		lf->access = access_syslog3;
	    if (!lf->conn)
		lf->conn = conn_syslog3;
	    lf->flag_syslog = BISTATE_YES;
	    lf->log_write = &log_write_common;
	    lf->log_flush = &log_flush_syslog;
	    lf->syslog_priority = common_data.syslog_level | common_data.syslog_facility;
	} else if (!su_pton_p(&lf->syslog_destination, lf->dest, 514)) {
	    char str[100];
	    *str = 0;
	    lf->flag_syslog = BISTATE_YES;
	    lf->log_write = &log_write_common;
	    lf->log_flush = &log_flush_syslog_udp;
	    if (!lf->acct)
		lf->acct = acct_syslog;
	    if (!lf->author)
		lf->author = author_syslog;
	    if (!lf->access)
		lf->access = access_syslog;
	    if (!lf->conn)
		lf->conn = conn_syslog;
	    if ((lf->sock = su_socket(lf->syslog_destination.sa.sa_family, SOCK_DGRAM, 0)) < 0) {
		report(NULL, LOG_DEBUG, ~0, "su_socket (%s:%d): %s", __FILE__, __LINE__, strerror(errno));
		free(lf);
		return;
	    }
	    if (lf->syslog_destination.sa.sa_family == AF_UNIX && su_connect(lf->sock, &lf->syslog_destination)) {
		report(NULL, LOG_DEBUG, ~0, "su_connect (%s:%d): %s", __FILE__, __LINE__, strerror(errno));
		close(lf->sock);
		lf->sock = -1;
		free(lf);
		return;
	    }
	} else {
	    report(NULL, LOG_INFO, ~0, "parse error (%s:%d): '%s' doesn't look like a valid log destination", __FILE__, __LINE__, lf->dest);
	    free(lf);
	    return;
	}
    }

    if (!r->logdestinations)
	r->logdestinations = RB_tree_new(compare_log, NULL);
    RB_insert(r->logdestinations, lf);
}

void log_add(struct sym *sym, rb_tree_t ** rbtp, char *s, tac_realm * r)
{
    struct logfile *res = NULL;
    struct logfile *lf = alloca(sizeof(struct logfile));
    lf->name = s;
    if (!*rbtp)
	*rbtp = RB_tree_new(compare_log, NULL);
    while (r) {
	if (r->logdestinations) {
	    if ((res = RB_lookup(r->logdestinations, lf))) {
		RB_insert(*rbtp, res);
		return;
	    }
	}
	r = r->parent;
    }

    parse_error(sym, "log destination '%s' not found", lf->name);
}

struct log_item *parse_log_format(struct sym *sym)
{
    struct log_item *start = NULL;
    struct log_item **li = &start;
    char *n;
    char *in = strdup(sym->buf);
    while (*in) {
	*li = calloc(1, sizeof(struct log_item));
	if (!start)
	    start = *li;
	if ((n = strstr(in, "${"))) {
	    char *sep;
	    *n = 0;
	    if (n != in) {
		(*li)->token = S_string;
		(*li)->text = in;
		li = &(*li)->next;
		*li = calloc(1, sizeof(struct log_item));
	    }
	    n += 2;
	    in = n;
	    n = strchr(in, '}');
	    if (!n)
		parse_error(sym, "closing bracket not found");
	    *n = 0;
	    n++;
	    for (sep = in; sep < n && *sep != ','; sep++);
	    if (sep != n) {
		*sep++ = 0;
		(*li)->separator = sep;
		(*li)->separator_len = strlen(sep);
	    }
	    (*li)->token = keycode(in);
	    switch ((*li)->token) {
	    case S_cmd:
	    case S_args:
	    case S_rargs:
		if (!(*li)->separator) {
		    (*li)->separator = " ";
		    (*li)->separator_len = 1;
		}
	    case S_nas:
	    case S_nac:
	    case S_proxy:
	    case S_peer:
	    case S_user:
	    case S_profile:
	    case S_service:
	    case S_result:
	    case S_port:
	    case S_hint:
	    case S_host:
	    case S_hostname:
	    case S_msgid:
	    case S_accttype:
	    case S_priority:
	    case S_action:
	    case S_privlvl:
	    case S_authen_action:
	    case S_authen_type:
	    case S_authen_service:
	    case S_authen_method:
	    case S_message:
	    case S_umessage:
	    case S_rule:
	    case S_path:
	    case S_uid:
	    case S_gid:
	    case S_gids:
	    case S_home:
	    case S_root:
	    case S_shell:
	    case S_memberof:
	    case S_dn:
	    case S_vrf:
	    case S_label:
	    case S_tls_conn_version:
	    case S_tls_conn_cipher:
	    case S_tls_peer_cert_issuer:
	    case S_tls_peer_cert_subject:
	    case S_tls_conn_cipher_strength:
	    case S_tls_peer_cn:
		break;
	    case S_config_file:
		(*li)->token = S_string;
		(*li)->text = strdup(sym->filename);
		break;
	    case S_config_line:
		{
		    char buf[20];
		    snprintf(buf, sizeof(buf), "%d", sym->line);
		    (*li)->token = S_string;
		    (*li)->text = strdup(buf);
		}
		break;
	    default:
		parse_error(sym, "log variable '%s' is not recognized", in);
	    }
	    in = n;
	} else {
	    (*li)->token = S_string;
	    (*li)->text = in;
	    break;
	}
	li = &(*li)->next;
    }
    sym_get(sym);
    return start;
}

static size_t ememcpy(char *dest, char *src, size_t n, size_t remaining)
{
    size_t res = 0;
    size_t wlen;

    while (n && remaining - res > 10) {
	if (*src == '\\') {
	    *dest++ = *src;
	    *dest++ = *src;
	    res += 2;
	    src++, n--;
	} else if (is_print(src, remaining, &wlen)) {
	    while (wlen > 0) {
		*dest = *src;
		dest++, src++, wlen--, res++, n--;
	    }
	} else {
	    *dest++ = '\\';
	    *dest++ = '0' + (7 & ((*src & 0xff) >> 6));
	    *dest++ = '0' + (7 & ((*src & 0xff) >> 3));
	    *dest++ = '0' + (7 & *src);
	    res += 4;
	    src++, n--;
	}
    }
    return res;
}

char *eval_log_format(tac_session * session, struct context *ctx, struct logfile *lf, struct log_item *start, time_t sec, size_t *outlen)
{
    char buf[8000];
    char *b = buf;
    size_t total_len = 0;
    struct log_item *li;
    for (li = start; li; li = li->next) {
	size_t len = 0;
	char *s = NULL;
	if (li->text) {
	    struct tm *tm = localtime(&sec);
	    len = strftime(b, sizeof(buf) - total_len, li->text, tm);
	    total_len += len;
	    b += len;
	    continue;
	}
	if (session) {
	    switch (li->token) {
	    case S_user:
		s = session->username;
		len = session->username_len;
		break;
	    case S_profile:
		if (session->profile) {
		    s = session->profile->name;
		    len = session->profile->name_len;
		}
		break;
	    case S_nac:
		s = session->nac_address_ascii;
		len = session->nac_address_ascii_len;
		break;
	    case S_msgid:
		s = session->msgid;
		len = session->msgid_len;
		break;
	    case S_port:
		s = session->nas_port;
		len = session->nas_port_len;
		break;
	    case S_hint:
		s = session->hint;
		len = session->hint_len;
		break;
	    case S_authen_action:
		s = session->authen_action;
		len = session->authen_action_len;
		break;
	    case S_authen_type:
		s = session->authen_type;
		len = session->authen_type_len;
		break;
	    case S_authen_service:
		s = session->authen_service;
		len = session->authen_service_len;
		break;
	    case S_authen_method:
		s = session->authen_method;
		len = session->authen_method_len;
		break;
	    case S_message:
		s = session->msg;
		len = session->msg_len;
		break;
	    case S_umessage:
		s = session->user_msg;
		len = session->user_msg_len;
		break;
	    case S_label:
		s = session->label;
		len = session->label_len;
		break;
	    case S_cmd:
	    case S_args:
	    case S_rargs:
		{
		    int separate = 0;
		    u_char arg_cnt = 0;
		    u_char *arg_len, *argp;
		    switch (li->token) {
		    case S_cmd:
		    case S_args:
			arg_cnt = session->arg_cnt;
			arg_len = session->arg_len;
			argp = session->argp;
			break;
		    case S_rargs:
			arg_cnt = session->arg_out_cnt;
			arg_len = session->arg_out_len;
			argp = session->argp_out;
			break;
		    default:;
		    }

		    for (; arg_cnt; arg_cnt--, arg_len++) {
			char *s;
			size_t l;
			s = (char *) argp;
			l = (size_t) *arg_len;

			if (li->token == S_cmd) {
			    if (l > 3 && (!strncmp(s, "cmd=", 4) || !strncmp(s, "cmd*", 4)))
				l -= 4, s += 4;
			    else if (l > 7 && !strncmp(s, "cmd-arg=", 8))
				l -= 8, s += 8;
			    else {
				argp += (size_t) *arg_len;;
				continue;
			    }
			}
			if (separate && li->separator) {
			    len = ememcpy(b, li->separator, li->separator_len, sizeof(buf) - total_len);
			    total_len += len;
			    b += len;
			    if (total_len > sizeof(buf) - 20)
				break;
			}
			len = ememcpy(b, s, l, sizeof(buf) - total_len);
			total_len += len;
			b += len;
			if (total_len > sizeof(buf) - 20)
			    break;
			argp += (size_t) *arg_len;;
			separate = 1;
		    }
		    continue;
		}
	    case S_result:
		s = session->result;
		len = session->result_len;
		break;
	    case S_action:
		s = session->action;
		len = session->action_len;
		break;
	    case S_accttype:
		s = session->acct_type;
		len = session->acct_type_len;
		break;
	    case S_service:
		s = session->service;
		len = session->service_len;
		break;
	    case S_privlvl:
		s = session->privlvl;
		len = session->privlvl_len;
		break;
	    case S_rule:
		s = session->rule;
		len = session->rule_len;
		break;
	    default:
		if (session->user && session->user->avc) {
		    switch (li->token) {
		    case S_path:
			s = session->user->avc->arr[AV_A_PATH];
			break;
		    case S_uid:
			s = session->user->avc->arr[AV_A_UID];
			break;
		    case S_gid:
			s = session->user->avc->arr[AV_A_GID];
			break;
		    case S_home:
			s = av_get(session->user->avc, AV_A_HOME);
			break;
		    case S_root:
			s = session->user->avc->arr[AV_A_ROOT];
			break;
		    case S_shell:
			s = session->user->avc->arr[AV_A_SHELL];
			break;
		    case S_gids:
			s = session->user->avc->arr[AV_A_GIDS];
			break;
		    case S_memberof:
			s = session->user->avc->arr[AV_A_MEMBEROF];
			break;
		    case S_dn:
			s = session->user->avc->arr[AV_A_DN];
			break;
		    default:;
		    }
		}
	    }
	}
	if (!s && ctx) {
	    switch (li->token) {
	    case S_accttype:
		s = ctx->acct_type;
		len = ctx->acct_type_len;
		break;
	    case S_msgid:
		s = ctx->msgid;
		len = ctx->msgid_len;
		break;
	    case S_nas:
		s = ctx->nas_address_ascii;
		len = ctx->nas_address_ascii_len;
		break;
	    case S_proxy:
		s = ctx->proxy_addr_ascii;
		len = ctx->proxy_addr_ascii_len;
		break;
	    case S_peer:
		s = ctx->peer_addr_ascii;
		len = ctx->peer_addr_ascii_len;
		break;
	    case S_host:
		s = ctx->host->name;
		len = ctx->host->name_len;
		break;
	    case S_vrf:
		s = ctx->vrf;
		len = ctx->vrf_len;
		break;
	    default:;
	    }
	}
	if (!s) {
	    switch (li->token) {
	    case S_priority:
		if (lf) {
		    s = lf->priority;
		    len = lf->priority_len;
		}
		break;
	    case S_hostname:
		s = config.hostname;
		len = config.hostname_len;
		break;
#ifdef WITH_TLS
	    case S_tls_conn_version:
		s = (char *) ctx->tls_conn_version;
		len = ctx->tls_conn_version_len;
		break;
	    case S_tls_conn_cipher:
		s = (char *) ctx->tls_conn_cipher;
		len = ctx->tls_conn_cipher_len;
		break;
	    case S_tls_peer_cert_issuer:
		s = (char *) ctx->tls_peer_cert_issuer;
		len = ctx->tls_peer_cert_issuer_len;
		break;
	    case S_tls_peer_cert_subject:
		s = (char *) ctx->tls_peer_cert_subject;
		len = ctx->tls_peer_cert_subject_len;
		break;
	    case S_tls_conn_cipher_strength:
		s = ctx->tls_conn_cipher_strength;
		len = ctx->tls_conn_cipher_strength_len;
		break;
	    case S_tls_peer_cn:
		s = ctx->tls_peer_cn;
		len = ctx->tls_peer_cn_len;
		break;
#endif
	    default:;
	    }
	}
	if (s) {
	    if (!len)
		len = strlen(s);
	    len = ememcpy(b, s, len, sizeof(buf) - total_len);
	    total_len += len;
	    b += len;
	    if (total_len > sizeof(buf) - 20)
		break;
	}
    }
    *b = 0;
    if (outlen)
	*outlen = total_len;
    if (session)
	return memlist_strdup(session->memlist, buf);
    return mempool_strdup(ctx->pool, buf);
}

void log_exec(tac_session * session, struct context *ctx, enum token token, time_t sec)
{
    tac_realm *r = ctx->realm;
    rb_node_t *rbn;
    while (r) {
	rb_tree_t *rbt;
	switch (token) {
	case S_accounting:
	    rbt = r->acctlog;
	    break;
	case S_access:
	case S_authentication:
	    rbt = r->accesslog;
	    break;
	case S_authorization:
	    rbt = r->authorlog;
	    break;
	case S_connection:
	    rbt = r->connlog;
	    break;
	default:
	    rbt = NULL;
	}
	if (rbt) {
	    for (rbn = RB_first(rbt); rbn; rbn = RB_next(rbn)) {
		struct logfile *lf = RB_payload(rbn, struct logfile *);
		struct log_item *li = NULL;
		char *s;
		size_t len;

		switch (token) {
		case S_accounting:
		    li = lf->acct;
		    break;
		case S_access:
		case S_authentication:
		    li = lf->access;
		    break;
		case S_authorization:
		    li = lf->author;
		    break;
		case S_connection:
		    li = lf->conn;
		    break;
		default:
		    return;
		}

		s = eval_log_format(session, ctx, lf, li, sec, &len);
		log_start(lf, NULL);
		lf->log_write(lf, s, len);
		lf->log_flush(lf);
	    }
	}
	r = r->parent;
    }
}

struct memlist;
typedef struct memlist memlist_t;

struct memlist {
    u_int count;
    memlist_t *next;
#define MEMLIST_ARR_SIZE 128
    void *arr[MEMLIST_ARR_SIZE];
};

struct memlist *memlist_create(void)
{
    return calloc(1, sizeof(memlist_t));
}

void **memlist_add(memlist_t * list, void *p)
{
    void **res = NULL;
    if (p && list) {
	if (list->count == MEMLIST_ARR_SIZE) {
	    list->next = memlist_create();
	    list = list->next;
	}
	list->arr[list->count] = p;
	res = &list->arr[list->count];
	list->count++;
    }
    return res;
}

void *memlist_malloc(memlist_t * list, size_t size)
{
    void *p = calloc(1, size ? size : 1);

    if (p) {
	memlist_add(list, p);
	return p;
    }
    report(NULL, LOG_ERR, ~0, "malloc %d failure", (int) size);
    tac_exit(EX_OSERR);
}

void *memlist_realloc(memlist_t * list, void *p, size_t size)
{
    if (p) {
	u_int i = 0;
	while (list && i < list->count) {
	    if (list->arr[i] == p)
		break;
	    i++;
	    if (i == MEMLIST_ARR_SIZE) {
		i = 0;
		list = list->next;
	    }
	}
	p = realloc(p, size);
	if (list && i < list->count)
	    list->arr[i] = p;
	else {
	    report(NULL, LOG_ERR, ~0, "realloc %d failure", (int) size);
	    tac_exit(EX_OSERR);
	}
	return p;
    }
    return memlist_malloc(list, size);
}

void memlist_destroy(memlist_t * list)
{
    while (list) {
	u_int i;
	memlist_t *next = NULL;
	for (i = 0; i < list->count; i++, next = list->next)
	    free(list->arr[i]);
	free(list);
	list = next;
    }
}

char *memlist_strdup(memlist_t * list, char *s)
{
    char *p = strdup(s);

    if (p) {
	memlist_add(list, p);
	return p;
    }
    report(NULL, LOG_ERR, ~0, "strdup failure");
    tac_exit(EX_OSERR);
}

char *memlist_strndup(memlist_t * list, u_char * s, int len)
{
    char *p = strndup((char *) s, len);

    if (p) {
	memlist_add(list, p);
	return p;
    }
    report(NULL, LOG_ERR, ~0, "strndup failure");
    tac_exit(EX_OSERR);
}
