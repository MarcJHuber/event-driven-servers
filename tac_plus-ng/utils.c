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

static int tac_lockfd(int lockfd)
{
    static struct flock flock = {.l_type = F_WRLCK,.l_whence = SEEK_SET };
    return fcntl(lockfd, F_SETLK, &flock);
}

static int tac_unlockfd(int lockfd)
{
    static struct flock flock = {.l_type = F_UNLCK,.l_whence = SEEK_SET };
    return fcntl(lockfd, F_SETLK, &flock);
}

struct logfile {
    TAC_NAME_ATTRIBUTES;
    char *dest;			/* log file dest specification */
    char *dest2;		/* secondary dest specification for syslog */
    struct context_logfile *ctx;	/* current log context */
    void (*log_write)(struct logfile *, char *, size_t);
    void (*log_flush)(struct logfile *);
    int syslog_priority;
    sockaddr_union *syslog_src;
    sockaddr_union syslog_dst;
    sockaddr_union syslog_dst2;
    int sock;
    int sock2;
    time_t last;
    struct log_item *acct;
    struct log_item *access;
    struct log_item *author;
    struct log_item *conn;
    struct log_item *rad_access;
    struct log_item *rad_acct;
    str_t syslog_ident;
    str_t priority;
    str_t *separator;		// ${FS}
    struct log_item *prefix;
    struct log_item *postfix;
    unsigned int logsequence;
     BISTATE(flag_syslog);
     BISTATE(flag_sync);
     BISTATE(flag_pipe);
     BISTATE(flag_staticpath);
     BISTATE(flag_udp_spoof);
     BISTATE(warned);
    enum token timestamp_format;
    size_t buf_limit;
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
			    off_t o = writev(lf->ctx->fd, v, count);
			    if (o > 0)
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
	    if (lf->warned == BISTATE_NO)
		report(NULL, LOG_INFO, ~0, "\"%s\" respawning too fast", lf->dest);
	    lf->warned = BISTATE_YES;
	    return;
	}

	lf->warned = BISTATE_NO;
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
		// io_destroy(common_data.io, NULL);
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
		tac_exit(EX_OSERR);
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
	    openlog(lf->syslog_ident.txt, 0, lf->syslog_priority & ~7);
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

static void log_write_async(struct logfile *lf, char *buf, size_t len)
{
    if (lf->ctx) {
	if (lf->buf_limit > 0 && buffer_getlen(lf->ctx->buf) > lf->buf_limit)
	    lf->ctx->buf = buffer_free_all(lf->ctx->buf);
	lf->ctx->buf = buffer_write(lf->ctx->buf, buf, len);
	io_set_o(common_data.io, lf->ctx->fd);
    }
}

static void log_write_common(struct logfile *lf, char *buf, size_t len)
{
    if (lf->ctx) {
	if (lf->buf_limit > 0 && buffer_getlen(lf->ctx->buf) > lf->buf_limit)
	    lf->ctx->buf = buffer_free_all(lf->ctx->buf);
	lf->ctx->buf = buffer_write(lf->ctx->buf, buf, len);
    }
}

static int is_print(char *text, size_t len, size_t *wlen)
{
    /* Returns TRUE for printable one-byte characters and valid
     * UTF-8 multi-byte characters. An alternative would be to
     * use iswprint(3), but I didn't get that to work correctly.
     */
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

    for (size_t i = 1; i < *wlen; i++) {
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
	int r = -1;
#define ISAF(A,AF) (lf->syslog_ ## A.sa.sa_family == AF)
	if (ISAF(dst, AF_UNIX))
	    r = send(lf->sock, lf->ctx->buf->buf + lf->ctx->buf->offset, (int) len, 0);
	if (r < 0 && lf->syslog_src)
	    r = sendto_spoof(lf->syslog_src, &lf->syslog_dst, lf->ctx->buf->buf + lf->ctx->buf->offset, (size_t) len);
	if (r < 0 && lf->syslog_src)
	    r = sendto_spoof(lf->syslog_src, &lf->syslog_dst2, lf->ctx->buf->buf + lf->ctx->buf->offset, (size_t) len);
	if (r < 0)
	    r = sendto(lf->sock, lf->ctx->buf->buf + lf->ctx->buf->offset, (int) len, 0, &lf->syslog_dst.sa, su_len(&lf->syslog_dst));
	if (r < 0)
	    report(NULL, LOG_DEBUG, ~0, "send/sendto (%s:%d): %s", __FILE__, __LINE__, strerror(errno));
	lf->ctx->buf = buffer_release(lf->ctx->buf, &len);
    }
}

static void log_flush_sync(struct logfile *lf)
{
    logwrite_sync(lf->ctx, lf->ctx->fd);
}

int logs_flushed(tac_realm *r)
{
    if (r->logdestinations) {
	for (rb_node_t * rbn = RB_first(r->logdestinations); rbn; rbn = RB_next(rbn)) {
	    struct logfile *lf = RB_payload(rbn, struct logfile *);
	    if (!lf->flag_pipe && !lf->flag_sync && lf->ctx && buffer_getlen(lf->ctx->buf))
		return 0;
	}
    }
    if (r->realms) {
	for (rb_node_t * rbn = RB_first(r->realms); rbn; rbn = RB_next(rbn)) {
	    if (!logs_flushed(RB_payload(rbn, tac_realm *)))
		return 0;
	}
    }
    return -1;
}

struct log_item *parse_log_format(struct sym *, mem_t *);

struct log_item *parse_log_format_inline(char *format, char *file, int line)
{
    struct sym sym = {.filename = file,.line = line };
    sym.in = sym.tin = format;
    sym.len = sym.tlen = strlen(sym.in);
    sym_init(&sym);
    return parse_log_format(&sym, NULL);
}

void parse_log(struct sym *sym, tac_realm *r)
{
    static struct log_item *access_log = NULL;
    static struct log_item *author_log = NULL;
    static struct log_item *acct_log = NULL;
    static struct log_item *conn_log = NULL;
    static struct log_item *rad_access_log = NULL;
    static struct log_item *rad_acct_log = NULL;

    static struct log_item *file_pre = NULL;
    static struct log_item *file_post = NULL;
    static struct log_item *syslog_pre = NULL;
    static struct log_item *syslog_post = NULL;
    static struct log_item *syslog3_pre = NULL;
    static struct log_item *syslog3_post = NULL;

    static str_t syslog_fs = { "|", 1 };
    static str_t file_fs = { "\t", 1 };

    struct logfile *lf = calloc(1, sizeof(struct logfile));
    if (sym->code == S_equal)
	sym_get(sym);
    str_set(&lf->name, strdup(sym->buf), 0);
    sym_get(sym);
    if (r->logdestinations && RB_search(r->logdestinations, lf))
	parse_error(sym, "log destination '%s' already defined", lf->name);
    lf->dest = "syslog";
    str_set(&lf->syslog_ident, "tacplus", 0);
    lf->syslog_priority = common_data.syslog_level | common_data.syslog_facility;
    lf->sock = -1;
    lf->sock2 = -1;
    lf->buf_limit = 64000;

    if (sym->code == S_openbra) {
	sym_get(sym);
	while (sym->code != S_closebra) {
	    switch (sym->code) {
	    case S_authentication:
	    case S_access:
		sym_get(sym);
		parse(sym, S_format);
		parse(sym, S_equal);
		lf->access = parse_log_format(sym, NULL);
		continue;
	    case S_authorization:
		sym_get(sym);
		parse(sym, S_format);
		parse(sym, S_equal);
		lf->author = parse_log_format(sym, NULL);
		continue;
	    case S_accounting:
		sym_get(sym);
		parse(sym, S_format);
		parse(sym, S_equal);
		lf->acct = parse_log_format(sym, NULL);
		continue;
	    case S_connection:
		sym_get(sym);
		parse(sym, S_format);
		parse(sym, S_equal);
		lf->conn = parse_log_format(sym, NULL);
		continue;
	    case S_radius_access:
		sym_get(sym);
		parse(sym, S_format);
		parse(sym, S_equal);
		lf->rad_access = parse_log_format(sym, NULL);
		continue;
	    case S_radius_accounting:
		sym_get(sym);
		parse(sym, S_format);
		parse(sym, S_equal);
		lf->rad_acct = parse_log_format(sym, NULL);
		continue;
	    case S_destination:
		sym_get(sym);
		parse(sym, S_equal);
		lf->dest = strdup(sym->buf);
		sym_get(sym);
		if (sym->code == S_comma) {
		    sym_get(sym);
		    lf->dest2 = strdup(sym->buf);
		    sym_get(sym);
		}
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
		    str_set(&lf->syslog_ident, strdup(sym->buf), 0);
		    sym_get(sym);
		    continue;
		case S_source:
		    sym_get(sym);
		    parse(sym, S_spoofing);
		    parse(sym, S_equal);
		    lf->flag_udp_spoof = parse_bool(sym) ? 1 : 0;
		    continue;
		default:
		    parse_error_expect(sym, S_facility, S_severity, S_ident, S_unknown, S_source);
		}
	    case S_timestamp:
		sym_get(sym);
		parse(sym, S_equal);
		switch (sym->code) {
		case S_RFC3164:
		case S_RFC5424:
		    lf->timestamp_format = sym->code;
		    sym_get(sym);
		    break;
		default:
		    parse_error_expect(sym, S_RFC3164, S_RFC5424, S_unknown);
		}
		continue;
	    case S_prefix:
		sym_get(sym);
		parse(sym, S_equal);
		lf->prefix = parse_log_format(sym, NULL);
		sym_get(sym);
		continue;
	    case S_postfix:
		sym_get(sym);
		parse(sym, S_equal);
		lf->postfix = parse_log_format(sym, NULL);
		continue;
	    case S_FS:
	    case S_separator:
		sym_get(sym);
		parse(sym, S_equal);
		lf->separator = calloc(1, sizeof(str_t));
		str_set(lf->separator, strdup(sym->buf), 0);
		sym_get(sym);
		continue;
	    case S_buffer:
		sym_get(sym);
		parse(sym, S_limit);
		parse(sym, S_equal);
		lf->buf_limit = parse_int(sym);
		continue;
	    default:
		parse_error_expect(sym, S_destination, S_syslog, S_access, S_authorization, S_accounting, S_connection, S_closebra,
				   S_prefix, S_postfix, S_separator, S_radius_access, S_radius_accounting, S_timestamp, S_buffer, S_unknown);
	    }
	}
	sym_get(sym);
    }
    char buf[10];
    size_t buf_len = snprintf(buf, sizeof(buf), "%d", lf->syslog_priority);
    str_set(&lf->priority, strdup(buf), buf_len);

    if (!access_log) {
#define PR "\""			// inline parsing prefix/suffix

#define S "${nas}${FS}${user}${FS}${port}${FS}${nac}${FS}${accttype}${FS}${service}${FS}${cmd}"
	acct_log = parse_log_format_inline(PR S PR, __FILE__, __LINE__);
#undef S

#define S "${nas}${FS}${user}${FS}${port}${FS}${nac}${FS}${profile}${FS}${result}${FS}${service}${FS}${cmd}"
	author_log = parse_log_format_inline(PR S PR, __FILE__, __LINE__);
#undef S

#define S "${nas}${FS}${user}${FS}${port}${FS}${nac}${FS}${action} ${hint}"
	access_log = parse_log_format_inline(PR S PR, __FILE__, __LINE__);
#undef S

#define S "${accttype}${FS}${conn.protocol}${FS}${peer.address}${FS}${peer.port}${FS}${server.address}${FS}${server.port}${FS}${tls.conn.version}${FS}${tls.peer.cert.issuer}${FS}${tls.peer.cert.subject}"
	conn_log = parse_log_format_inline(PR S PR, __FILE__, __LINE__);
#undef S

#define S "${nas}${FS}${user}${FS}${port}${FS}${nac}${FS}${accttype}${FS}${action} ${hint}${FS}${args, }${FS}${rargs, }"
	rad_access_log = parse_log_format_inline(PR S PR, __FILE__, __LINE__);
#undef S

#define S "${nas}${FS}${user}${FS}${port}${FS}${nac}${FS}${accttype}${FS}${service}${FS}${args, }"
	rad_acct_log = parse_log_format_inline(PR S PR, __FILE__, __LINE__);
#undef S

	file_pre = parse_log_format_inline(PR "${TIMESTAMP} " PR, __FILE__, __LINE__);
	file_post = parse_log_format_inline(PR "\n" PR, __FILE__, __LINE__);
	syslog_pre = parse_log_format_inline(PR "<${priority}>${TIMESTAMP} ${hostname} ${ident}[${pid}]: ${msgid}${FS}" PR, __FILE__, __LINE__);
	syslog_post = parse_log_format_inline(PR "" PR, __FILE__, __LINE__);
	syslog3_post = parse_log_format_inline(PR "" PR, __FILE__, __LINE__);
	syslog3_pre = parse_log_format_inline(PR "${msgid}${FS}" PR, __FILE__, __LINE__);
#undef PR
    }

    if (!lf->acct)
	lf->acct = acct_log;
    if (!lf->author)
	lf->author = author_log;
    if (!lf->access)
	lf->access = access_log;
    if (!lf->conn)
	lf->conn = conn_log;
    if (!lf->rad_access)
	lf->rad_access = rad_access_log;
    if (!lf->rad_acct)
	lf->rad_acct = rad_acct_log;

    switch (lf->dest[0]) {
    case '/':
	lf->flag_staticpath = (strchr(lf->dest, '%') == NULL);
	lf->flag_pipe = 0;
	lf->flag_sync = 0;
	lf->log_write = &log_write_async;
	lf->log_flush = &log_flush_async;
	break;
    case '>':
	lf->dest++;
	lf->log_write = &log_write_common;
	lf->log_flush = &log_flush_sync;
	lf->flag_sync = BISTATE_YES;
	break;
    case '|':
	lf->dest++;
	lf->flag_pipe = BISTATE_YES;
	lf->log_write = &log_write_async;
	lf->log_flush = &log_flush_async;
	break;
    default:
	if (!lf->separator)
	    lf->separator = &syslog_fs;
	if (lf->timestamp_format == S_unknown)
	    lf->timestamp_format = S_RFC3164;
	if (!strcmp(lf->dest, codestring[S_syslog].txt)) {
	    if (!lf->prefix)
		lf->prefix = syslog3_pre;
	    if (!lf->postfix)
		lf->postfix = syslog3_post;
	    lf->flag_syslog = BISTATE_YES;
	    lf->log_write = &log_write_common;
	    lf->log_flush = &log_flush_syslog;
	} else if (!su_pton_p(&lf->syslog_dst, lf->dest, 514)) {
	    if (!lf->prefix)
		lf->prefix = syslog_pre;
	    if (!lf->postfix)
		lf->postfix = syslog_post;
	    lf->flag_syslog = BISTATE_YES;
	    lf->log_write = &log_write_common;
	    lf->log_flush = &log_flush_syslog_udp;
	    if ((lf->sock = su_socket(lf->syslog_dst.sa.sa_family, SOCK_DGRAM, 0)) < 0) {
		report(NULL, LOG_DEBUG, ~0, "su_socket (%s:%d): %s", __FILE__, __LINE__, strerror(errno));
		free(lf);	// FIXME -- the free(lf) calls here don't free everything
		return;
	    }
	    fcntl(lf->sock, F_SETFD, fcntl(lf->sock, F_GETFD, 0) | FD_CLOEXEC);
	    if (lf->dest2 && !su_pton_p(&lf->syslog_dst2, lf->dest2, 514)) {
		if ((lf->sock2 = su_socket(lf->syslog_dst2.sa.sa_family, SOCK_DGRAM, 0)) < 0) {
		    report(NULL, LOG_DEBUG, ~0, "su_socket (%s:%d): %s", __FILE__, __LINE__, strerror(errno));
		    close(lf->sock);
		    free(lf);
		    return;
		}
	    }
	    if (lf->sock2 > -1)
		fcntl(lf->sock, F_SETFD, fcntl(lf->sock2, F_GETFD, 0) | FD_CLOEXEC);
	    if (ISAF(dst, AF_UNIX) && su_connect(lf->sock, &lf->syslog_dst)) {
		report(NULL, LOG_DEBUG, ~0, "su_connect (%s:%d): %s", __FILE__, __LINE__, strerror(errno));
		close(lf->sock);
		free(lf);
		return;
	    }
	} else {
	    report(NULL, LOG_INFO, ~0, "parse error (%s:%d): '%s' doesn't look like a valid log destination", __FILE__, __LINE__, lf->dest);
	    free(lf);
	    return;
	}
    }
    if (!lf->separator)
	lf->separator = &file_fs;
    if (!lf->prefix)
	lf->prefix = file_pre;
    if (!lf->postfix)
	lf->postfix = file_post;

    if (!r->logdestinations)
	r->logdestinations = RB_tree_new(compare_name, NULL);
    RB_insert(r->logdestinations, lf);
}

void log_add(struct sym *sym, rb_tree_t **rbtp, char *s, tac_realm *r)
{
    if (!*rbtp)
	*rbtp = RB_tree_new(compare_name, NULL);
    struct logfile lf = {.name.txt = s,.name.len = strlen(s) };
    while (r) {
	if (r->logdestinations) {
	    struct logfile *res = NULL;
	    if ((res = RB_lookup(r->logdestinations, &lf))) {
		RB_insert(*rbtp, res);
		return;
	    }
	}
	r = r->parent;
    }

    parse_error(sym, "log destination '%s' not found", s);
}

struct log_item *parse_log_format(struct sym *sym, mem_t *mem)
{
    struct log_item *start = NULL;
    struct log_item **li = &start;
    char *n;
    char *in = mem_strdup(mem, sym->buf);
    while (*in) {
	*li = mem_alloc(mem, sizeof(struct log_item));
	if (!start)
	    start = *li;
	if ((n = strstr(in, "${"))) {
	    char *sep;
	    *n = 0;
	    if (n != in) {
		(*li)->token = S_string;
		(*li)->text = in;
		li = &(*li)->next;
		*li = mem_alloc(mem, sizeof(struct log_item));
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
		str_set(&(*li)->separator, sep, 0);
	    }
	    char *m = strchr(in, ':');
	    if (m) {
		*m = 0;
		(*li)->text = m + 1;
	    }
	    (*li)->token = keycode(in);
	    if (m)
		*m = ':';
	    switch ((*li)->token) {
	    case S_cmd:
	    case S_args:
	    case S_rargs:
		if (!(*li)->separator.txt)
		    str_set(&(*li)->separator, " ", 1);
	    case S_nas:
	    case S_nac:
	    case S_client:
	    case S_clientdns:
	    case S_clientname:
	    case S_clientaddress:
	    case S_context:
	    case S_conn_protocol:
	    case S_conn_transport:
	    case S_devicedns:
	    case S_devicename:
	    case S_deviceaddress:
	    case S_proxy:
	    case S_peer:
	    case S_peer_address:
	    case S_peer_port:
	    case S_user:
	    case S_user_original:
	    case S_profile:
	    case S_service:
	    case S_result:
	    case S_deviceport:
	    case S_port:
	    case S_type:
	    case S_hint:
	    case S_host:
	    case S_device:
	    case S_hostname:
	    case S_server_name:
	    case S_server_address:
	    case S_server_port:
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
	    case S_custom_0:
	    case S_custom_1:
	    case S_custom_2:
	    case S_custom_3:
	    case S_vrf:
	    case S_realm:
	    case S_label:
	    case S_identity_source:
	    case S_tls_conn_version:
	    case S_tls_conn_cipher:
	    case S_tls_peer_cert_issuer:
	    case S_tls_peer_cert_subject:
	    case S_tls_conn_cipher_strength:
	    case S_tls_peer_cn:
	    case S_tls_psk_identity:
	    case S_ssh_key_hash:
	    case S_ssh_key_id:
	    case S_tls_conn_sni:
	    case S_tls_peer_cert_sha1:
	    case S_tls_peer_cert_sha256:
	    case S_nacname:
	    case S_nasname:
	    case S_mavis_latency:
	    case S_session_id:
	    case S_logsequence:
	    case S_pid:
	    case S_ident:
	    case S_PASSWORD:
	    case S_RESPONSE:
	    case S_PASSWORD_OLD:
	    case S_PASSWORD_NEW:
	    case S_PASSWORD_ABORT:
	    case S_PASSWORD_AGAIN:
	    case S_PASSWORD_NOMATCH:
	    case S_PASSWORD_MINREQ:
	    case S_PERMISSION_DENIED:
	    case S_ENABLE_PASSWORD:
	    case S_PASSWORD_CHANGE_DIALOG:
	    case S_PASSWORD_CHANGED:
	    case S_BACKEND_FAILED:
	    case S_CHANGE_PASSWORD:
	    case S_ACCOUNT_EXPIRES:
	    case S_PASSWORD_EXPIRED:
	    case S_PASSWORD_EXPIRES:
	    case S_PASSWORD_INCORRECT:
	    case S_RESPONSE_INCORRECT:
	    case S_USERNAME:
	    case S_USER_ACCESS_VERIFICATION:
	    case S_DENIED_BY_ACL:
	    case S_AUTHFAIL_BANNER:
	    case S_TIMESTAMP:
	    case S_FS:
	    case S_dacl:
		break;
	    case S_config_file:
		(*li)->token = S_string;
		(*li)->text = mem_strdup(mem, sym->filename);
		break;
	    case S_config_line:
		{
		    char buf[20];
		    snprintf(buf, sizeof(buf), "%d", sym->line);
		    (*li)->token = S_string;
		    (*li)->text = mem_strdup(mem, buf);
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

    if (!start) {
	static struct log_item li = {.token = S_string,.text = "" };
	start = &li;
    }

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

static str_t *eval_log_format_user(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session)
	return &session->username;
    return NULL;
}

static str_t *eval_log_format_user_original(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session)
	return &session->username_orig;
    return NULL;
}

static str_t *eval_log_format_profile(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session && session->profile)
	return &session->profile->name;
    return NULL;
}

static str_t *eval_log_format_nac(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session)
	return &session->nac_addr_ascii;
    return NULL;
}

static str_t *eval_log_format_msgid(tac_session *session, struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (session)
	return session->msgid;
    if (ctx)
	return ctx->msgid;
    return NULL;
}

static str_t *eval_log_format_port(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session)
	return &session->port;
    if (ctx)
	return &ctx->device_port_ascii;
    return NULL;
}

static str_t *eval_log_format_type(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session)
	return session->type;
    return NULL;
}

static str_t *eval_log_format_hint(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session)
	return &session->hint;
    return NULL;
}

static str_t *eval_log_format_authen_action(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session)
	return session->authen_action;
    return NULL;
}

static str_t *eval_log_format_authen_type(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session)
	return session->authen_type;
    return NULL;
}

static str_t *eval_log_format_authen_service(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session)
	return session->authen_service;
    return NULL;
}

static str_t *eval_log_format_authen_method(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session)
	return session->authen_method;
    return NULL;
}

static str_t *eval_log_format_message(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session)
	return &session->msg;
    return NULL;
}

static str_t *eval_log_format_umessage(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session)
	return &session->user_msg;
    return NULL;
}

static str_t *eval_log_format_label(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session)
	return &session->label;
    return NULL;
}

static str_t *eval_log_format_result(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session)
	return session->result;
    return NULL;
}

static str_t *eval_log_format_action(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session)
	return &session->action;
    return NULL;
}

static str_t *eval_log_format_accttype(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session)
	return session->acct_type;
    if (ctx)
	return ctx->acct_type;
    return NULL;
}

static str_t *eval_log_format_service(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session)
	return &session->service;
    return NULL;
}

str_t *eval_log_format_privlvl(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session) {
	static char buf[4];
	static str_t s = {.txt = buf };
	s.len = 0;
	if (session->priv_lvl > 99)
	    buf[s.len++] = '0' + session->priv_lvl / 100;
	if (session->priv_lvl > 9)
	    buf[s.len++] = '0' + (session->priv_lvl / 10) % 10;
	buf[s.len++] = '0' + session->priv_lvl % 10;
	buf[s.len] = 0;
	return &s;
    }
    return NULL;
}

static str_t str;

static str_t *eval_log_format_ssh_key_hash(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session && session->ssh_key_hash)
	return str_set(&str, session->ssh_key_hash, 0);
    return NULL;
}

static str_t *eval_log_format_ssh_key_id(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session && session->ssh_key_id)
	return str_set(&str, session->ssh_key_id, 0);
    return NULL;
}

static str_t *eval_log_format_rule(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session)
	return session->rulename;
    return NULL;
}

static str_t *eval_log_format_path(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session && session->user && session->user->avc)
	return str_set(&str, session->user->avc->arr[AV_A_PATH], 0);
    return NULL;
}

static str_t *eval_log_format_uid(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session && session->user && session->user->avc)
	return str_set(&str, session->user->avc->arr[AV_A_UID], 0);
    return NULL;
}

static str_t *eval_log_format_gid(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session && session->user && session->user->avc)
	return str_set(&str, session->user->avc->arr[AV_A_GID], 0);
    return NULL;
}

static str_t *eval_log_format_home(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session && session->user && session->user->avc)
	return str_set(&str, session->user->avc->arr[AV_A_HOME], 0);
    return NULL;
}

static str_t *eval_log_format_root(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session && session->user && session->user->avc)
	return str_set(&str, session->user->avc->arr[AV_A_ROOT], 0);
    return NULL;
}

static str_t *eval_log_format_shell(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session && session->user && session->user->avc)
	return str_set(&str, session->user->avc->arr[AV_A_SHELL], 0);
    return NULL;
}

static str_t *eval_log_format_gids(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session && session->user && session->user->avc)
	return str_set(&str, session->user->avc->arr[AV_A_GIDS], 0);
    return NULL;
}

static str_t *eval_log_format_memberof(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session && session->user && session->user->avc)
	return str_set(&str, session->user->avc->arr[AV_A_MEMBEROF], 0);
    return NULL;
}

static str_t *eval_log_format_dn(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session && session->user && session->user->avc)
	return str_set(&str, session->user->avc->arr[AV_A_DN], 0);
    return NULL;
}

static str_t *eval_log_format_identity_source(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session && session->user && session->user->avc)
	return str_set(&str, session->user->avc->arr[AV_A_IDENTITY_SOURCE], 0);
    return NULL;
}

static str_t *eval_log_format_nas(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (ctx)
	return &ctx->device_addr_ascii;
    return NULL;
}

static str_t *eval_log_format_proxy(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (ctx)
	return &ctx->proxy_addr_ascii;
    return NULL;
}

static str_t *eval_log_format_peer(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (ctx)
	return &ctx->peer_addr_ascii;
    return NULL;
}

static str_t *eval_log_format_host(tac_session *session, struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (session)
	return &session->host->name;
    if (ctx)
	return &ctx->host->name;
    return NULL;
}

static str_t *eval_log_format_vrf(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (ctx)
	return &ctx->vrf;
    return NULL;
}

static str_t *eval_log_format_realm(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (ctx)
	return &ctx->realm->name;
    return NULL;
}

static str_t *eval_log_format_PASSWORD(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (ctx)
	return str_set(&str, ctx->host->user_messages[UM_PASSWORD], 0);
    return NULL;
}

static str_t *eval_log_format_RESPONSE(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (ctx)
	return str_set(&str, ctx->host->user_messages[UM_RESPONSE], 0);
    return NULL;
}

static str_t *eval_log_format_PASSWORD_OLD(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (ctx)
	return str_set(&str, ctx->host->user_messages[UM_PASSWORD_OLD], 0);
    return NULL;
}

static str_t *eval_log_format_PASSWORD_NEW(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (ctx)
	return str_set(&str, ctx->host->user_messages[UM_PASSWORD_NEW], 0);
    return NULL;
}

static str_t *eval_log_format_PASSWORD_ABORT(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (ctx)
	return str_set(&str, ctx->host->user_messages[UM_PASSWORD_ABORT], 0);
    return NULL;
}

static str_t *eval_log_format_PASSWORD_AGAIN(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (ctx)
	return str_set(&str, ctx->host->user_messages[UM_PASSWORD_AGAIN], 0);
    return NULL;
}

static str_t *eval_log_format_PASSWORD_NOMATCH(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (ctx)
	return str_set(&str, ctx->host->user_messages[UM_PASSWORD_NOMATCH], 0);
    return NULL;
}

static str_t *eval_log_format_PASSWORD_MINREQ(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (ctx)
	return str_set(&str, ctx->host->user_messages[UM_PASSWORD_MINREQ], 0);
    return NULL;
}

static str_t *eval_log_format_PERMISSION_DENIED(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (ctx) {
	str_set(&str, ctx->host->user_messages[UM_PERMISSION_DENIED], 0);
	return &str;
    }
    return NULL;
}

static str_t *eval_log_format_ENABLE_PASSWORD(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (ctx)
	return str_set(&str, ctx->host->user_messages[UM_ENABLE_PASSWORD], 0);
    return NULL;
}

static str_t *eval_log_format_PASSWORD_CHANGE_DIALOG(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf
						     __attribute__((unused)))
{
    if (ctx)
	return str_set(&str, ctx->host->user_messages[UM_PASSWORD_CHANGE_DIALOG], 0);
    return NULL;
}

static str_t *eval_log_format_PASSWORD_CHANGED(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (ctx)
	return str_set(&str, ctx->host->user_messages[UM_PASSWORD_CHANGED], 0);
    return NULL;
}

static str_t *eval_log_format_BACKEND_FAILED(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (ctx)
	return str_set(&str, ctx->host->user_messages[UM_BACKEND_FAILED], 0);
    return NULL;
}

static str_t *eval_log_format_CHANGE_PASSWORD(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (ctx)
	return str_set(&str, ctx->host->user_messages[UM_CHANGE_PASSWORD], 0);
    return NULL;
}

static str_t *eval_log_format_ACCOUNT_EXPIRES(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (ctx)
	return str_set(&str, ctx->host->user_messages[UM_ACCOUNT_EXPIRES], 0);
    return NULL;
}

static str_t *eval_log_format_PASSWORD_EXPIRES(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (ctx)
	return str_set(&str, ctx->host->user_messages[UM_PASSWORD_EXPIRES], 0);
    return NULL;
}

static str_t *eval_log_format_PASSWORD_EXPIRED(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (ctx)
	return str_set(&str, ctx->host->user_messages[UM_PASSWORD_EXPIRED], 0);
    return NULL;
}

static str_t *eval_log_format_PASSWORD_INCORRECT(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf
						 __attribute__((unused)))
{
    if (ctx)
	return str_set(&str, ctx->host->user_messages[UM_PASSWORD_INCORRECT], 0);
    return NULL;
}

static str_t *eval_log_format_RESPONSE_INCORRECT(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf
						 __attribute__((unused)))
{
    if (ctx)
	return str_set(&str, ctx->host->user_messages[UM_RESPONSE_INCORRECT], 0);
    return NULL;
}

static str_t *eval_log_format_USERNAME(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (ctx)
	return str_set(&str, ctx->host->user_messages[UM_USERNAME], 0);
    return NULL;
}

static str_t *eval_log_format_USER_ACCESS_VERIFICATION(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf
						       __attribute__((unused)))
{
    if (ctx)
	return str_set(&str, ctx->host->user_messages[UM_USER_ACCESS_VERIFICATION], 0);
    return NULL;
}

static str_t *eval_log_format_DENIED_BY_ACL(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (ctx)
	return str_set(&str, ctx->host->user_messages[UM_DENIED_BY_ACL], 0);
    return NULL;
}

static str_t *eval_log_format_AUTHFAIL_BANNER(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session && ctx && ctx->host->authfail_banner) {
	str.txt = eval_log_format(session, session->ctx, NULL, ctx->host->authfail_banner, io_now.tv_sec, &str.len);
	return &str;
    }
    return NULL;
}


static str_t *eval_log_format_priority(tac_session *session __attribute__((unused)), struct context *ctx __attribute((unused)), struct logfile *lf)
{
    if (lf)
	return &lf->priority;
    return NULL;
}

static str_t *eval_log_format_hostname(tac_session *session __attribute__((unused)), struct context *ctx __attribute__((unused)), struct logfile *lf
				       __attribute__((unused)))
{
    return &config.hostname;
}

static str_t *eval_log_format_server_port(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (ctx)
	return &ctx->server_port_ascii;
    return NULL;
}

static str_t *eval_log_format_peer_port(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (ctx)
	return &ctx->peer_port_ascii;
    return NULL;
}

static str_t *eval_log_format_server_address(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (ctx)
	return &ctx->server_addr_ascii;
    return NULL;
}

static str_t *eval_log_format_nasname(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (ctx && ctx->device_dns_name.txt && *ctx->device_dns_name.txt)
	return &ctx->device_dns_name;
    return NULL;
}

static str_t *eval_log_format_nacname(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session && session->nac_dns_name.txt && *session->nac_dns_name.txt)
	return &session->nac_dns_name;
    return NULL;
}

static str_t *eval_log_format_custom_0(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session && session->user && session->user->avc)
	return str_set(&str, session->user->avc->arr[AV_A_CUSTOM_0], 0);
    return NULL;
}

static str_t *eval_log_format_custom_1(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session && session->user && session->user->avc)
	return str_set(&str, session->user->avc->arr[AV_A_CUSTOM_1], 0);
    return NULL;
}

static str_t *eval_log_format_custom_2(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session && session->user && session->user->avc)
	return str_set(&str, session->user->avc->arr[AV_A_CUSTOM_2], 0);
    return NULL;
}

static str_t *eval_log_format_custom_3(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session && session->user && session->user->avc)
	return str_set(&str, session->user->avc->arr[AV_A_CUSTOM_3], 0);
    return NULL;
}

static str_t *eval_log_format_context(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session)
	return str_set(&str, tac_script_get_exec_context(session), 0);
    return NULL;
}

static str_t *eval_log_format_mavis_latency(tac_session *session, struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (session) {
	char buf[128];
	snprintf(buf, sizeof(buf), "%lu", session->mavis_latency);
	return str_set(&str, mem_strdup(session->mem, buf), 0);
    }
    if (ctx) {
	char buf[128];
	snprintf(buf, sizeof(buf), "%lu", ctx->mavis_latency);
	return str_set(&str, mem_strdup(ctx->mem, buf), 0);
    }
    return NULL;
}

static str_t *eval_log_format_session_id(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf __attribute__((unused)))
{
    if (session) {
	char buf[128];
	snprintf(buf, sizeof(buf), "%.8x", ntohl(session->session_id));
	return str_set(&str, mem_strdup(session->mem, buf), 0);
    }
    return NULL;
}

static str_t *eval_log_format_logsequence(tac_session *session, struct context *ctx __attribute__((unused)), struct logfile *lf)
{
    if (lf) {
	char buf[128];
	snprintf(buf, sizeof(buf), "%u", lf->logsequence++);
	return str_set(&str, mem_strdup(session ? session->mem : ctx->mem, buf), 0);
    }
    return NULL;
}

static str_t *eval_log_format_pid(tac_session *session __attribute__((unused)), struct context *ctx __attribute__((unused)), struct logfile *lf
				  __attribute__((unused)))
{
    static char buf[32] = { 0 };
    static size_t l = 0;
    if (!*buf)
	l = snprintf(buf, sizeof(buf), "%lu", (unsigned long) getpid());
    return str_set(&str, buf, l);
}

static str_t *eval_log_format_ident(tac_session *session __attribute__((unused)), struct context *ctx __attribute__((unused)), struct logfile *lf)
{
    if (lf)
	return &lf->syslog_ident;
    return NULL;
}

static str_t *eval_log_format_conn_protocol(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (ctx)
	return &codestring[ctx->udp ? S_udp : S_tcp];
    return NULL;
}

static str_t *eval_log_format_conn_transport(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (ctx) {
#ifdef WITH_SSL
	if (ctx->tls)
	    return &codestring[ctx->udp ? S_dtls : S_tls];
#endif
	return &codestring[ctx->udp ? S_udp : S_tcp];
    }
    return NULL;
}

static str_t *eval_log_format_TIMESTAMP(tac_session *session __attribute__((unused)), struct context *ctx __attribute__((unused)), struct logfile *lf)
{
    static char buf[64] = { 0 };
    enum token timestamp_format = lf ? lf->timestamp_format : S_unknown;
    const char *format = NULL;

    switch (timestamp_format) {
    case S_RFC3164:
	format = "%b %e %H:%M:%S";
	break;
    case S_RFC5424:
	//format = "%Y-%m-%dT%H:%M:%S.%06N%:z";
	format = "%Y-%m-%dT%H:%M:%S.      %z";
	break;
    case S_none:
	return NULL;
    default:
	format = "%Y-%m-%d %H:%M:%S %z";
	break;
    }

    struct tm *tm = localtime(&io_now.tv_sec);
    size_t l = strftime(buf, sizeof(buf), format, tm);
    if (timestamp_format == S_RFC5424) {
	char *t = buf + 20;
	long int usec = io_now.tv_usec;
	for (int i = 5; i > -1; i--) {
	    t[i] = '0' + (usec % 10);
	    usec /= 10;
	}
	buf[34] = buf[33];
	buf[33] = buf[32];
	buf[32] = buf[31];
	buf[31] = buf[30];
	buf[30] = buf[29];
	buf[29] = ':';
	l++;
    }
    str_set(&str, buf, l);

    return &str;
}

static str_t *eval_log_format_FS(tac_session *session __attribute__((unused)), struct context *ctx __attribute__((unused)), struct logfile *lf)
{
    if (lf)
	return lf->separator;
    return NULL;
}

#if defined(WITH_SSL)
static str_t *eval_log_format_tls_conn_version(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (ctx)
	return &ctx->tls_conn_version;
    return NULL;
}

static str_t *eval_log_format_tls_conn_cipher(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (ctx)
	return &ctx->tls_conn_cipher;
    return NULL;
}

static str_t *eval_log_format_tls_peer_cert_issuer(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf
						   __attribute__((unused)))
{
    if (ctx)
	return &ctx->tls_peer_cert_issuer;
    return NULL;
}

static str_t *eval_log_format_tls_peer_cert_subject(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf
						    __attribute__((unused)))
{
    if (ctx)
	return &ctx->tls_peer_cert_subject;
    return NULL;
}

static str_t *eval_log_format_tls_conn_cipher_strength(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf
						       __attribute__((unused)))
{
    if (ctx)
	return &ctx->tls_conn_cipher_strength;
    return NULL;
}

static str_t *eval_log_format_tls_peer_cn(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (ctx)
	return &ctx->tls_peer_cn;
    return NULL;
}

static str_t *eval_log_format_tls_psk_identity(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (ctx)
	return &ctx->tls_psk_identity;
    return NULL;
}

static str_t *eval_log_format_tls_conn_sni(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf __attribute__((unused)))
{
    if (ctx)
	return &ctx->tls_sni;
    return NULL;
}

static str_t *eval_log_format_tls_peer_cert_sha1(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf
						 __attribute__((unused)))
{
    if (ctx->tls) {
	struct fingerprint *fp = ctx->fingerprint;
	while (fp && fp->type != S_tls_peer_cert_sha1)
	    fp = fp->next;
	if (fp) {
	    static char buf[SHA_DIGEST_LENGTH * 3];
	    char *b = buf;
	    dump_hex(fp->hash, SHA_DIGEST_LENGTH, &b);
	    return str_set(&str, buf, 0);
	}
    }
    return NULL;
}

static str_t *eval_log_format_tls_peer_cert_sha256(tac_session *session __attribute__((unused)), struct context *ctx, struct logfile *lf
						   __attribute__((unused)))
{
    if (ctx->tls) {
	struct fingerprint *fp = ctx->fingerprint;
	while (fp && fp->type != S_tls_peer_cert_sha256)
	    fp = fp->next;
	if (fp) {
	    static char buf[SHA256_DIGEST_LENGTH * 3];
	    char *b = buf;
	    dump_hex(fp->hash, SHA256_DIGEST_LENGTH, &b);
	    return str_set(&str, buf, 0);
	}
    }
    return NULL;
}
#endif

char *eval_log_format(tac_session *session, struct context *ctx, struct logfile *lf, struct log_item *start, time_t sec, size_t *outlen)
{
    static int initialized = 0;
    static str_t *((*efun[S_null]) (tac_session *, struct context *, struct logfile *)) = { 0 };
    mem_t *mem = session ? session->mem : ctx->mem;

    if (!initialized) {
	initialized = 1;
	efun[S_ACCOUNT_EXPIRES] = &eval_log_format_ACCOUNT_EXPIRES;
	efun[S_AUTHFAIL_BANNER] = &eval_log_format_AUTHFAIL_BANNER;
	efun[S_BACKEND_FAILED] = &eval_log_format_BACKEND_FAILED;
	efun[S_CHANGE_PASSWORD] = &eval_log_format_CHANGE_PASSWORD;
	efun[S_DENIED_BY_ACL] = &eval_log_format_DENIED_BY_ACL;
	efun[S_ENABLE_PASSWORD] = &eval_log_format_ENABLE_PASSWORD;
	efun[S_PASSWORD] = &eval_log_format_PASSWORD;
	efun[S_PASSWORD_ABORT] = &eval_log_format_PASSWORD_ABORT;
	efun[S_PASSWORD_AGAIN] = &eval_log_format_PASSWORD_AGAIN;
	efun[S_PASSWORD_CHANGE_DIALOG] = &eval_log_format_PASSWORD_CHANGE_DIALOG;
	efun[S_PASSWORD_CHANGED] = &eval_log_format_PASSWORD_CHANGED;
	efun[S_PASSWORD_EXPIRED] = &eval_log_format_PASSWORD_EXPIRED;
	efun[S_PASSWORD_EXPIRES] = &eval_log_format_PASSWORD_EXPIRES;
	efun[S_PASSWORD_INCORRECT] = &eval_log_format_PASSWORD_INCORRECT;
	efun[S_PASSWORD_MINREQ] = &eval_log_format_PASSWORD_MINREQ;
	efun[S_PASSWORD_NEW] = &eval_log_format_PASSWORD_NEW;
	efun[S_PASSWORD_NOMATCH] = &eval_log_format_PASSWORD_NOMATCH;
	efun[S_PASSWORD_OLD] = &eval_log_format_PASSWORD_OLD;
	efun[S_PERMISSION_DENIED] = &eval_log_format_PERMISSION_DENIED;
	efun[S_RESPONSE] = &eval_log_format_RESPONSE;
	efun[S_RESPONSE_INCORRECT] = &eval_log_format_RESPONSE_INCORRECT;
	efun[S_USERNAME] = &eval_log_format_USERNAME;
	efun[S_USER_ACCESS_VERIFICATION] = &eval_log_format_USER_ACCESS_VERIFICATION;
	efun[S_TIMESTAMP] = &eval_log_format_TIMESTAMP;
	efun[S_FS] = &eval_log_format_FS;
	efun[S_accttype] = &eval_log_format_accttype;
	efun[S_action] = &eval_log_format_action;
	efun[S_authen_action] = &eval_log_format_authen_action;
	efun[S_authen_method] = &eval_log_format_authen_method;
	efun[S_authen_service] = &eval_log_format_authen_service;
	efun[S_authen_type] = &eval_log_format_authen_type;
	efun[S_conn_protocol] = &eval_log_format_conn_protocol;
	efun[S_conn_transport] = &eval_log_format_conn_transport;
	efun[S_dn] = &eval_log_format_dn;
	efun[S_gid] = &eval_log_format_gid;
	efun[S_gids] = &eval_log_format_gids;
	efun[S_hint] = &eval_log_format_hint;
	efun[S_home] = &eval_log_format_home;
	efun[S_host] = &eval_log_format_host;
	efun[S_device] = &eval_log_format_host;
	efun[S_devicename] = &eval_log_format_hostname;
	efun[S_server_name] = &eval_log_format_hostname;
	efun[S_server_address] = &eval_log_format_server_address;
	efun[S_server_port] = &eval_log_format_server_port;
	efun[S_hostname] = &eval_log_format_hostname;
	efun[S_label] = &eval_log_format_label;
	efun[S_memberof] = &eval_log_format_memberof;
	efun[S_message] = &eval_log_format_message;
	efun[S_msgid] = &eval_log_format_msgid;
	efun[S_clientname] = &eval_log_format_nac;
	efun[S_clientaddress] = &eval_log_format_nac;
	efun[S_context] = &eval_log_format_context;
	efun[S_nac] = &eval_log_format_nac;
	efun[S_deviceaddress] = &eval_log_format_nas;
	efun[S_nas] = &eval_log_format_nas;
	efun[S_path] = &eval_log_format_path;
	efun[S_peer] = &eval_log_format_peer;
	efun[S_peer_address] = &eval_log_format_peer;
	efun[S_peer_port] = &eval_log_format_peer_port;
	efun[S_port] = &eval_log_format_port;
	efun[S_deviceport] = &eval_log_format_port;
	efun[S_priority] = &eval_log_format_priority;
	efun[S_privlvl] = &eval_log_format_privlvl;
	efun[S_profile] = &eval_log_format_profile;
	efun[S_proxy] = &eval_log_format_proxy;
	efun[S_realm] = &eval_log_format_realm;
	efun[S_result] = &eval_log_format_result;
	efun[S_root] = &eval_log_format_root;
	efun[S_rule] = &eval_log_format_rule;
	efun[S_service] = &eval_log_format_service;
	efun[S_shell] = &eval_log_format_shell;
	efun[S_ssh_key_hash] = &eval_log_format_ssh_key_hash;
	efun[S_ssh_key_id] = &eval_log_format_ssh_key_id;
	efun[S_type] = &eval_log_format_type;
	efun[S_uid] = &eval_log_format_uid;
	efun[S_umessage] = &eval_log_format_umessage;
	efun[S_user] = &eval_log_format_user;
	efun[S_user_original] = &eval_log_format_user_original;
	efun[S_vrf] = &eval_log_format_vrf;
	efun[S_identity_source] = &eval_log_format_identity_source;
	efun[S_clientdns] = &eval_log_format_nacname;
	efun[S_nacname] = &eval_log_format_nacname;
	efun[S_devicedns] = &eval_log_format_nasname;
	efun[S_nasname] = &eval_log_format_nasname;
	efun[S_mavis_latency] = &eval_log_format_mavis_latency;
	efun[S_session_id] = &eval_log_format_session_id;
	efun[S_logsequence] = &eval_log_format_logsequence;
	efun[S_pid] = &eval_log_format_pid;
	efun[S_ident] = &eval_log_format_ident;
	efun[S_custom_0] = &eval_log_format_custom_0;
	efun[S_custom_1] = &eval_log_format_custom_1;
	efun[S_custom_2] = &eval_log_format_custom_2;
	efun[S_custom_3] = &eval_log_format_custom_3;
#if defined(WITH_SSL)
	efun[S_tls_conn_cipher] = &eval_log_format_tls_conn_cipher;
	efun[S_tls_conn_cipher_strength] = &eval_log_format_tls_conn_cipher_strength;
	efun[S_tls_conn_version] = &eval_log_format_tls_conn_version;
	efun[S_tls_peer_cert_issuer] = &eval_log_format_tls_peer_cert_issuer;
	efun[S_tls_peer_cert_subject] = &eval_log_format_tls_peer_cert_subject;
	efun[S_tls_peer_cn] = &eval_log_format_tls_peer_cn;
	efun[S_tls_psk_identity] = &eval_log_format_tls_psk_identity;
	efun[S_tls_conn_sni] = &eval_log_format_tls_conn_sni;
	efun[S_tls_peer_cert_sha1] = &eval_log_format_tls_peer_cert_sha1;
	efun[S_tls_peer_cert_sha256] = &eval_log_format_tls_peer_cert_sha256;
#endif
    }

    char buf[8000];
    char *b = buf;
    size_t total_len = 0;

    for (struct log_item * li = start; li; li = li->next) {
	size_t len = 0;
	str_t *s = NULL;
	if (session && li->token == S_dacl) {
	    tac_realm *r = session->ctx->realm;
	    struct rad_dacl *dacl = lookup_dacl(li->text, r);
	    if (sizeof(buf) - total_len > 40 + strlen(li->text)) {
		len += snprintf(b, sizeof(buf) - total_len, ACSACL "%s-%.8x", li->text, dacl ? dacl->version : (uint32_t) io_now.tv_sec);
		b += len;
		total_len += len;
	    }
	    continue;
	}
	if (li->text) {
	    struct tm *tm = localtime(&sec);
	    len = strftime(b, sizeof(buf) - total_len, li->text, tm);
	    total_len += len;
	    b += len;
	    continue;
	}
	if (efun[li->token])
	    s = efun[li->token] (session, ctx, lf);
	else if (session) {
	    enum token token = li->token;
	    switch (token) {
	    case S_cmd:
		if (session && session->service.txt && strcmp(session->service.txt, "shell"))
		    token = S_args;
	    case S_args:
	    case S_rargs:
		if (session->radius_data) {
		    u_char *data;
		    size_t data_len;

		    switch (token) {
		    case S_rargs:
			data = session->radius_data->data;
			data_len = session->radius_data->data_len;
			break;
		    default:;
			token = S_args;	// override "cmd"
			data = RADIUS_DATA(session->radius_data->pak_in);
			data_len = RADIUS_DATA_LEN(session->radius_data->pak_in);
			break;
		    }
		    size_t buf_len = buf + sizeof(buf) - b;
		    size_t old_len = buf_len;
		    rad_attr_val_dump(mem, data, data_len, &b, &buf_len, NULL, li->separator.txt, li->separator.len);
		    // rad_attr_val_dump called with buf != NULL. Both b and buf_len are already adjused, but
		    // total_len isn't.
		    total_len += old_len - buf_len;
		    if (total_len > sizeof(buf) - 20)
			break;
		    continue;
		} else {
		    int separate = 0;
		    u_char arg_cnt = 0;
		    u_char *arg_len, *argp;
		    switch (token) {
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

			if (l > 8 && !strncmp(s, "service=", 8)) {
			    argp += (size_t) *arg_len;
			    continue;
			}

			if (token == S_cmd) {
			    if (l > 3 && (!strncmp(s, "cmd=", 4) || !strncmp(s, "cmd*", 4)))
				l -= 4, s += 4;
			    else if (l > 7 && !strncmp(s, "cmd-arg=", 8))
				l -= 8, s += 8;
			    else {
				argp += (size_t) *arg_len;
				continue;
			    }
			}
			if (separate && li->separator.txt) {
			    len = ememcpy(b, li->separator.txt, li->separator.len, sizeof(buf) - total_len);
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
			argp += (size_t) *arg_len;
			separate = 1;
		    }
		    continue;
		}
	    default:;
	    }
	}

	if (s && s->txt && s->txt[0]) {
	    len = s->len;
	    if (!len)
		len = strlen(s->txt);
	    if (li->token == S_umessage || li->token == S_AUTHFAIL_BANNER || li->token == S_FS || (session && session->eval_log_raw)) {
		if (sizeof(buf) - total_len > len + 20)
		    memcpy(b, s->txt, s->len);
	    } else
		len = ememcpy(b, s->txt, s->len, sizeof(buf) - total_len);
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
	return mem_strdup(session->mem, buf);
    return mem_strdup(ctx->mem, buf);
}

void log_exec(tac_session *session, struct context *ctx, enum token token, time_t sec)
{
    tac_realm *r = ctx->realm;
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
	case S_radius_access:
	    rbt = r->rad_accesslog;
	    break;
	case S_radius_accounting:
	    rbt = r->rad_acctlog;
	    break;
	default:
	    rbt = NULL;
	}
	if (rbt) {
	    for (rb_node_t * rbn = RB_first(rbt); rbn; rbn = RB_next(rbn)) {
		struct logfile *lf = RB_payload(rbn, struct logfile *);
		struct log_item *li = NULL;
		size_t len = 0;

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
		case S_radius_access:
		    li = lf->rad_access;
		    break;
		case S_radius_accounting:
		    li = lf->rad_acct;
		    break;
		default:
		    return;
		}

		sockaddr_union syslog_src;

		if (lf->flag_udp_spoof &&	//
		    (((ISAF(dst, AF_INET) || ISAF(dst2, AF_INET)) && !su_htop(&syslog_src, &ctx->device_addr, AF_INET)) ||
		     ((ISAF(dst, AF_INET6) || ISAF(dst2, AF_INET6)) && !su_htop(&syslog_src, &ctx->device_addr, AF_INET6))))
		    lf->syslog_src = &syslog_src;
		else
		    lf->syslog_src = NULL;

		char *pre = NULL, *post = NULL;
		size_t pre_len = 0, post_len = 0;
		if (lf->prefix)
		    pre = eval_log_format(session, ctx, lf, lf->prefix, sec, &pre_len);
		if (lf->postfix)
		    post = eval_log_format(session, ctx, lf, lf->postfix, sec, &post_len);

		char *s = eval_log_format(session, ctx, lf, li, sec, &len);
		log_start(lf, NULL);
		if (pre && *pre)
		    log_write_common(lf, pre, pre_len);
		if (post && *post) {
		    log_write_common(lf, s, len);
		    lf->log_write(lf, post, post_len);
		} else
		    lf->log_write(lf, s, len);

		lf->log_flush(lf);
	    }
	}
	r = r->parent;
    }
}
