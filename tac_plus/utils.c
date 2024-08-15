/*
   Copyright (C) 1999-2016 Marc Huber (Marc.Huber@web.de)
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

#ifdef WITH_PCRE2
#include <pcre2.h>
#endif

#include <regex.h>

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
    RB_tree_delete(pool);
}

rb_tree_t *mempool_create(void)
{
    return RB_tree_new(pool_cmp, free);
}

#ifdef WITH_PCRE2
rb_tree_t *tac_pcrepool_create(void)
{
    return RB_tree_new(pool_cmp, (void (*)(void *)) pcre2_code_free);
}
#endif

rb_tree_t *tac_regpool_create(void)
{
    return RB_tree_new(pool_cmp, (void (*)(void *)) regfree);
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
    struct flock flock = { .l_whence = SEEK_SET };

    flock.l_type = locktype;
    return fcntl(lockfd, F_SETLK, &flock);
}

#define tac_lockfd(A) tac_lock(A,F_WRLCK)
#define tac_unlockfd(A) tac_lock(A,F_UNLCK)

#define SYSLOG_COMPLIANCE_RFC3164 3164
#define SYSLOG_COMPLIANCE_RFC5424 5424

struct logfile {
    char *format;		/* log file format specification */
    char *name;			/* log file specification */
    struct context_logfile *ctx;	/* current log context */
    void (*log_write)(struct logfile *, char *, size_t);
    void (*log_write_hostname)(struct logfile *, char *, size_t, char *, size_t);
    void (*log_flush)(struct logfile *);
     BISTATE(flag_syslog);
     BISTATE(flag_sync);
     BISTATE(flag_pipe);
     BISTATE(flag_staticpath);
    int syslog_priority;
    char *syslog_ident;
    char *syslog_prefix;
    int syslog_compliance;
    char *date_format;
    char *log_separator;
    sockaddr_union syslog_destination;
    int sock;
    size_t syslog_prefix_len;
    size_t log_separator_len;
    time_t last;
};

static void log_start_one(struct logfile *, struct context_logfile *);

static void logdied(pid_t pid __attribute__((unused)), struct context_logfile *ctx, int status __attribute__((unused)))
{
    if (ctx) {
	io_close(common_data.io, ctx->fd);
	ctx->lf->ctx = NULL;
	if (ctx->buf) {
	    log_start_one(ctx->lf, ctx);
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

static struct context_logfile *new_context_logfile(char *path)
{
    struct context_logfile *ctx;
    int len;
    if (!path)
	path = "";
    len = strlen(path);
    ctx = calloc(1, sizeof(struct context_logfile) + len);
    memcpy(ctx->path, path, len);
    return ctx;
}

static void log_start_one(struct logfile *lf, struct context_logfile *deadctx)
{
    char newpath[PATH_MAX + 1];
    char *path = NULL;
    int cur = -1;

    if (deadctx) {
	path = deadctx->path;
    } else if (!lf->flag_syslog) {
	if (lf->flag_staticpath) {
	    path = lf->format;
	} else {
	    time_t dummy = (time_t) io_now.tv_sec;
	    struct tm *tm = localtime(&dummy);
	    if (!strftime(newpath, sizeof(newpath), lf->format, tm)) {
		report(NULL, LOG_DEBUG, ~0, "strftime failed for %s", lf->format);
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
	    report(NULL, LOG_INFO, ~0, "\"%s\" respawning too fast", lf->format);
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
		    lf->ctx = new_context_logfile(path);
		    io_child_set(pid, (void (*)(pid_t, void *, int))
				 logdied, (void *) lf->ctx);
		}
		lf->ctx->pid = pid;
	    }
	} else if (lf->flag_syslog) {
	    lf->ctx = new_context_logfile(NULL);
	    lf->flag_sync = 1;
	} else {
	    cur = open(path, O_CREAT | O_WRONLY | O_APPEND, config.mask);
	    if (cur < 0 && errno != EACCES) {
		create_dirs(path);
		cur = open(path, O_CREAT | O_WRONLY | O_APPEND, config.mask);
	    }
	    if (cur > -1 && !lf->ctx)
		lf->ctx = new_context_logfile(path);
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

static void log_write_date(rb_tree_t *);
static void log_write_hostname(rb_tree_t *, char *, size_t, char *, size_t);

void log_start(rb_tree_t * rbt, char *hostname, char *msgid)
{
    rb_node_t *rbn, *rbnext;
    for (rbn = RB_first(rbt); rbn; rbn = rbnext) {
	struct logfile *lf = RB_payload(rbn, struct logfile *);
	rbnext = RB_next(rbn);
	log_start_one(lf, NULL);
    }
    log_write_date(rbt);
    log_write_hostname(rbt, hostname, strlen(hostname), msgid, msgid ? strlen(msgid) : 0);
}

static void log_write_date(rb_tree_t * rbt)
{
    char dstr[1024];
    time_t dummy = (time_t) io_now.tv_sec;
    struct tm *tm = localtime(&dummy);
    rb_node_t *rbn, *rbnext;
    for (rbn = RB_first(rbt); rbn; rbn = rbnext) {
	struct logfile *lf = RB_payload(rbn, struct logfile *);
	if (lf->date_format[0]) {
	    if (lf->flag_syslog)
		lf->log_write(lf, lf->syslog_prefix, lf->syslog_prefix_len);
	    strftime(dstr, sizeof(dstr), lf->date_format, tm);
	    lf->log_write(lf, dstr, strlen(dstr));
	    if (lf->flag_syslog)
		lf->log_write(lf, " ", 1);
	    else if (lf->log_separator_len)
		lf->log_write(lf, lf->log_separator, lf->log_separator_len);
	}
	rbnext = RB_next(rbn);
    }
}

void log_write_separator(rb_tree_t * rbt)
{
    rb_node_t *rbn, *rbnext;
    for (rbn = RB_first(rbt); rbn; rbn = rbnext) {
	struct logfile *lf = RB_payload(rbn, struct logfile *);
	rbnext = RB_next(rbn);
	if (lf->log_separator_len)
	    lf->log_write(lf, lf->log_separator, lf->log_separator_len);
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

static void log_write_hostname_common(struct logfile *lf, char *buf, size_t len, char *msgid __attribute__((unused)), size_t msgid_len
				      __attribute__((unused)))
{
    lf->log_write(lf, buf, len);
    if (lf->log_separator_len)
	lf->log_write(lf, lf->log_separator, lf->log_separator_len);
}

static void log_write_hostname_syslog_udp(struct logfile *lf, char *buf, size_t len, char *msgid, size_t msgid_len __attribute__((unused)))
{
    char str[100];
    lf->log_write(lf, buf, len);
    if (lf->syslog_compliance == SYSLOG_COMPLIANCE_RFC5424)
	snprintf(str, sizeof(str), " %s - - %s ", lf->syslog_ident, msgid ? msgid : "-");
    else
	snprintf(str, sizeof(str), " %s ", lf->syslog_ident);
    lf->log_write(lf, str, strlen(str));
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

static void log_write_hostname(rb_tree_t * rbt, char *buf, size_t len, char *msgid, size_t msgid_len)
{
    rb_node_t *rbn, *rbnext;
    for (rbn = RB_first(rbt); rbn; rbn = rbnext) {
	struct logfile *lf = RB_payload(rbn, struct logfile *);
	rbnext = RB_next(rbn);
	lf->log_write_hostname(lf, buf, len, msgid, msgid_len);
    }
}

void log_write(rb_tree_t * rbt, char *buf, size_t len)
{
    rb_node_t *rbn, *rbnext;
    char ebuf[8192];
    char *e = ebuf, *b = buf;
    size_t i, elen, wlen;

    for (i = 0, elen = 0; i < len && elen < sizeof(ebuf) - 4;) {
	if (*b == '\\') {
	    *e++ = *b;
	    *e++ = *b;
	    elen += 2;
	    b++, i++;
	} else if (is_print(b, len - i, &wlen)) {
	    while (wlen > 0) {
		*e = *b;
		e++, b++, wlen--, elen++, i++;
	    }
	} else {
	    *e++ = '\\';
	    *e++ = '0' + (7 & ((*b & 0xff) >> 6));
	    *e++ = '0' + (7 & ((*b & 0xff) >> 3));
	    *e++ = '0' + (7 & *b);
	    elen += 4;
	    b++, i++;
	}
    }

    for (rbn = RB_first(rbt); rbn; rbn = rbnext) {
	struct logfile *lf = RB_payload(rbn, struct logfile *);
	rbnext = RB_next(rbn);
	lf->log_write(lf, ebuf, elen);
    }
}

void log_flush(rb_tree_t * rbt)
{
    rb_node_t *rbn, *rbnext;
    for (rbn = RB_first(rbt); rbn; rbn = rbnext) {
	struct logfile *lf = RB_payload(rbn, struct logfile *);
	rbnext = RB_next(rbn);
	lf->log_flush(lf);
    }
}

static void log_flush_async(struct logfile *lf __attribute__((unused)))
{
    lf->log_write(lf, "\n", 1);
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
    lf->log_write(lf, "\n", 1);
    logwrite_sync(lf->ctx, lf->ctx->fd);
}

int logs_flushed(void)
{
    rb_node_t *rbn, *rbnext;
    for (rbn = RB_first(config.logfiles); rbn; rbn = rbnext) {
	struct logfile *lf = RB_payload(rbn, struct logfile *);
	rbnext = RB_next(rbn);

	if (!lf->flag_pipe && !lf->flag_sync && lf->ctx && buffer_getlen(lf->ctx->buf))
	    return 0;
    }
    return -1;
}

int compare_log(const void *a, const void *b)
{
    int r;
    r = ((struct logfile *) a)->syslog_priority - ((struct logfile *) b)->syslog_priority;
    if (r)
	return r;
    r = ((struct logfile *) a)->syslog_compliance - ((struct logfile *) b)->syslog_compliance;
    if (r)
	return r;
    return strcmp(((struct logfile *) a)->name, ((struct logfile *) b)->name);
}

static int compare_logtemplate(const void *a, const void *b)
{
    return strcmp(((struct logfile *) a)->name, ((struct logfile *) b)->name);
}


void parse_log(struct sym *sym, tac_realm * r)
{
    struct logfile *lf = calloc(1, sizeof(struct logfile));
    sym_get(sym);
    lf->name = strdup(sym->buf);
    if (r->logfile_templates && RB_search(r->logfile_templates, lf))
	parse_error(sym, "log destination '%s' already defined", lf->name);
    lf->format = "syslog";
    lf->syslog_ident = "tacplus";
    lf->syslog_priority = common_data.syslog_level | common_data.syslog_facility;
    lf->syslog_compliance = SYSLOG_COMPLIANCE_RFC3164;
    lf->log_separator = r->log_separator;
    lf->log_separator_len = r->log_separator_len;
    sym_get(sym);
    parse(sym, S_openbra);
    while (sym->code != S_closebra) {
	switch (sym->code) {
	case S_destination:
	    sym_get(sym);
	    parse(sym, S_equal);
	    lf->format = strdup(sym->buf);
	    sym_get(sym);
	    continue;
	case S_log:
	    sym_get(sym);
	    parse(sym, S_separator);
	    parse(sym, S_equal);
	    lf->log_separator = strdup(sym->buf);
	    lf->log_separator_len = strlen(sym->buf);
	    sym_get(sym);
	    continue;
	case S_syslog:
	    lf->log_separator = "|";
	    lf->log_separator_len = 1;
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
	    case S_severity:
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
	    case S_compliance:
		sym_get(sym);
		parse(sym, S_equal);
		switch (sym->code) {
		case S_RFC3164:
		    lf->syslog_compliance = SYSLOG_COMPLIANCE_RFC3164;
		    break;
		case S_RFC5424:
		    lf->syslog_compliance = SYSLOG_COMPLIANCE_RFC5424;
		    break;
		default:
		    parse_error_expect(sym, S_RFC3164, S_RFC5424, S_unknown);
		}
		sym_get(sym);
		continue;
	    default:
		parse_error_expect(sym, S_facility, S_severity, S_ident, S_compliance, S_unknown);
	    }
	default:
	    parse_error_expect(sym, S_destination, S_log, S_syslog, S_unknown);
	}
    }
    sym_get(sym);
    if (!r->logfile_templates)
	r->logfile_templates = RB_tree_new(compare_logtemplate, NULL);

    RB_insert(r->logfile_templates, lf);
}



void log_add(rb_tree_t ** rbt, char *s, tac_realm * r)
{
    rb_node_t *rbn;
    struct logfile *lf = alloca(sizeof(struct logfile));
    struct logfile *lf_template = NULL;

    if (!*rbt)
	*rbt = RB_tree_new(compare_log, NULL);

    lf->name = s;
    if (r->logfile_templates && (rbn = RB_search(r->logfile_templates, lf))) {
	lf_template = RB_payload(rbn, struct logfile *);
	lf->syslog_priority = lf_template->syslog_priority;
	lf->syslog_compliance = lf_template->syslog_compliance;
	lf->syslog_ident = lf_template->syslog_ident;
    } else {
	lf->syslog_priority = common_data.syslog_level | common_data.syslog_facility;
	lf->syslog_compliance = SYSLOG_COMPLIANCE_RFC3164;
	lf->syslog_ident = "tacplus";
    }

    if ((rbn = RB_search(config.logfiles, lf)))
	lf = RB_payload(rbn, struct logfile *);
    else {
	lf = calloc(1, sizeof(struct logfile));
	if (lf_template) {
	    memcpy(lf, lf_template, sizeof(struct logfile));
	    s = lf->format;
	} else {
	    lf->name = strdup(s);
	    lf->syslog_priority = common_data.syslog_level | common_data.syslog_facility;
	    lf->syslog_compliance = SYSLOG_COMPLIANCE_RFC3164;
	    lf->syslog_ident = "tacplus";
	    lf->log_separator = r->log_separator;
	    lf->log_separator_len = r->log_separator_len;
	    lf->format = lf->name;
	}
	lf->date_format = r->date_format;
	switch (*s) {
	case '/':
	    lf->flag_staticpath = (strchr(s, '%') == NULL);
	    lf->flag_pipe = 0;
	    lf->flag_sync = 0;
	    lf->log_write = &log_write_async;
	    lf->log_write_hostname = &log_write_hostname_common;
	    lf->log_flush = &log_flush_async;
	    break;
	case '>':
	    lf->format++;
	    lf->log_write = &log_write_common;
	    lf->log_write_hostname = &log_write_hostname_common;
	    lf->log_flush = &log_flush_sync;
	    lf->flag_sync = BISTATE_YES;
	    break;
	case '|':
	    lf->format++;
	    lf->flag_pipe = BISTATE_YES;
	    lf->log_write = &log_write_async;
	    lf->log_write_hostname = &log_write_hostname_common;
	    lf->log_flush = &log_flush_async;
	    break;
	default:
	    if (!strcmp(s, codestring[S_syslog])) {
		lf->flag_syslog = BISTATE_YES;
		lf->log_write = &log_write_common;
		lf->log_write_hostname = &log_write_hostname_common;
		lf->log_flush = &log_flush_syslog;
		lf->syslog_priority = common_data.syslog_level | common_data.syslog_facility;
		lf->date_format = "";	// syslog(3) will add a suitable time-stamp
	    } else if (!su_pton_p(&lf->syslog_destination, lf->format, 514)) {
		char str[100];
		*str = 0;
		lf->flag_syslog = BISTATE_YES;
		lf->log_write = &log_write_common;
		lf->log_write_hostname = &log_write_hostname_syslog_udp;
		lf->log_flush = &log_flush_syslog_udp;
		if (lf->syslog_compliance == SYSLOG_COMPLIANCE_RFC5424) {
		    snprintf(str, sizeof(str), "<%d>1 ", lf->syslog_priority);
		    lf->date_format = "%Y-%m-%dT%H:%M:%S%z";
		} else {
		    snprintf(str, sizeof(str), "<%d>", lf->syslog_priority);
		    lf->date_format = "%b %e %T";
		}
		lf->syslog_prefix = strdup(str);
		lf->syslog_prefix_len = strlen(str);
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
		report(NULL, LOG_INFO, ~0, "parse error (%s:%d): '%s' doesn't look like a valid log destination", __FILE__, __LINE__, lf->format);
		free(lf);
		return;
	    }
	    break;
	}
	RB_insert(config.logfiles, lf);
    }
    RB_insert(*rbt, lf);
}
