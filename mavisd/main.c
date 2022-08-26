/*
 * main.c
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#ifndef __GNUC__
#define __attribute__(A)
#endif				/* __GNUC__ */

static const char rcsid[] __attribute__((used)) = "$Id$";

#define __MAIN__

#include "mavisd/headers.h"
#include "misc/version.h"
#include "misc/memops.h"
#include "mavis/av_send.h"
#include "misc/crc32.h"
#include "misc/sig_segv.h"
#include <sysexits.h>

#include "misc/base64.h"
#include "misc/rb.h"

static void usage(void)
{
    fprintf(stderr,
	    "Usage: %s <config> [<id>]\n"
	    "Version: " VERSION " (compiled: " __DATE__ " " __TIME__ ")\n"
	    "Copyright (C) 1998-2001 by Marc Huber <Marc.Huber@web.de>\n", common_data.progname);
    exit(EX_USAGE);
}

struct query {
    char *serial;
    sockaddr_union sa;
    int fd;
    u_int serial_crc;
};

static int compare_crc_serial(const void *v1, const void *v2)
{
    if (((struct query *) v1)->serial_crc < ((struct query *) v2)->serial_crc)
	return -1;
    if (((struct query *) v1)->serial_crc > ((struct query *) v2)->serial_crc)
	return +1;
    return strcmp(((struct query *) v1)->serial, ((struct query *) v2)->serial);
}

static int backlog = 0;
static int backlog_max = 0;
static int backlog_max_p = 0;
static rb_tree_t *deferred_by_serial;
static unsigned long long counter_query = 0, counter_p_query = 0;
static unsigned long long counter_retry = 0, counter_p_retry = 0;
static unsigned long long counter_answered = 0, counter_p_answered = 0;
static unsigned long long counter_expired = 0, counter_p_expired = 0;
static unsigned long long counter_err = 0, counter_p_err = 0;

static void mavis_io(struct context *ctx)
{
    av_ctx *avc = NULL;
    struct query *q;
    rb_node_t *r;
    char *serial;

    Debug((DEBUG_PROC, "mavis_io %p\n", ctx));
    switch (mavis_recv(mcx, &avc, ctx)) {
    case MAVIS_FINAL:
	break;
    case MAVIS_TIMEOUT:
	counter_expired++, counter_p_expired++;
    default:
	return;
    }

    if (!(serial = av_get(avc, AV_A_SERIAL)))
	return;

    q = alloca(sizeof(struct query));
    q->serial = serial;
    q->serial_crc = crc32_update(INITCRC32, (u_char *) serial, strlen(serial));

    if (!(r = RB_search(deferred_by_serial, q)))
	return;

    q = RB_payload(r, struct query *);

/* XXX -- move the unset functionality to a separate module? */
    if (!transmit_password) {
	av_unset(avc, AV_A_PASSWORD);
	av_unset(avc, AV_A_DBPASSWORD);
    }

    ctx = io_get_ctx(io, q->fd);
/* Send answer to client */
    av_send(avc, q->fd, &q->sa, ctx->blowfish);

/* Remove query from deferred queue */
    RB_delete(deferred_by_serial, r);
    backlog--;
    setproctitle("%s: backlog: %d", common_data.progname, backlog);

    counter_answered++, counter_p_answered++;
    return;
}				/* if */

void client_io(struct context *ctx, int cur)
{
/* We have incoming data. */
    char *serial;
    int res;
    ssize_t buflen;
    sockaddr_union sa;
    socklen_t sinlen = (socklen_t) sizeof(sockaddr_union);
    char *avt;
    char buf[BUFSIZE_MAVIS];
    av_ctx *avc;
    static struct query *q = NULL;

    if (!q)
	q = Xcalloc(1, sizeof(struct query));

    Debug((DEBUG_PROC, "client_io\n"));

/* Receive request from client */
    buflen = recvfrom(cur, buf, sizeof(buf) - 1, 0, &sa.sa, &sinlen);
    if (buflen <= 0)
	return;

    buf[buflen] = 0;

/* Decode data, if neccessary */
    if (ctx->blowfish)
	blowfish_dec(ctx->blowfish, (a_char *) buf, buflen);

/* Check client IP address */
    res = acl_check(&sa);
    if (!res) {
	char ibuf[INET6_ADDRSTRLEN];
	logmsg("Ignoring query from %s", su_ntop(&sa, ibuf, (socklen_t) sizeof(ibuf)));
	return;
    }

    counter_query++, counter_p_query++;

    avc = av_new(NULL, NULL);
    av_char_to_array(avc, buf, NULL);
    serial = av_get(avc, AV_A_SERIAL);
    if (!serial) {
	char ibuf[INET6_ADDRSTRLEN];
	logmsg("query from %s lacks serial", su_ntop(&sa, ibuf, (socklen_t) sizeof(ibuf)));
	counter_err++, counter_p_err++;
	av_free(avc);
	return;
    }

    q->serial = serial;
    q->serial_crc = crc32_update(INITCRC32, (u_char *) serial, strlen(serial));

    if (RB_search(deferred_by_serial, q)) {
	char ibuf[INET6_ADDRSTRLEN];
	Debug((DEBUG_PROC, "Duplicate detected\n"));
	logmsg("Ignoring duplicate query from %s (backlog: %d)", su_ntop(&sa, ibuf, (socklen_t) sizeof(ibuf)), backlog);
	counter_retry++, counter_p_retry++;
	av_free(avc);
	return;
    }

    if (av_get(avc, AV_A_RESULT)) {
	char ibuf[INET6_ADDRSTRLEN];
	Debug((DEBUG_PROC, "AV_A_RESULT already set. Spoofing?\n"));
	logmsg("Ignoring query with pre-set result code " "from %s (backlog: %d)", su_ntop(&sa, ibuf, (socklen_t) sizeof(ibuf)), backlog);
	counter_err++, counter_p_err++;
	av_free(avc);
	return;
    }

    avt = av_get(avc, AV_A_TYPE);

    if (!avt || !strncmp(avt, AV_V_TYPE_PRIVATE_PREFIX, AV_V_TYPE_PRIVATE_PREFIX_LEN)) {
	counter_err++, counter_p_err++;
	av_free(avc);
	return;
    }

    av_setcb(avc, (void *) mavis_io, (void *) q);

    switch (mavis_send(mcx, &avc)) {
    case MAVIS_DEFERRED:
	Debug((DEBUG_PROC, "mavis_send yields DEFERRED\n"));
	q->sa = sa;
	q->fd = cur;
	q->serial = Xstrdup(serial);
	RB_insert(deferred_by_serial, q);
	q = NULL;
	backlog++;
	if (backlog > backlog_max)
	    backlog_max = backlog;
	if (backlog > backlog_max_p)
	    backlog_max_p = backlog;
	setproctitle("%s: backlog: %d", common_data.progname, backlog);
	return;
    case MAVIS_TIMEOUT:
	counter_expired++, counter_p_expired++;
	break;

    case MAVIS_FINAL:
	if (!transmit_password) {
	    av_unset(avc, AV_A_PASSWORD);
	    av_unset(avc, AV_A_DBPASSWORD);
	}
	av_send(avc, cur, &sa, ctx->blowfish);
	counter_answered++, counter_p_answered++;
    }

    av_free(avc);
}

void udp_error(struct context *ctx __attribute__((unused)), int cur)
{
    /*
     * Linux sets the error flag if an UDP packet is sent to a local address
     * not bound to a socket. We need to resolve this by clearing the socket
     * error status.
     *
     */
    int sockerr;
    socklen_t sockerrlen = (socklen_t) sizeof(sockerr);
    getsockopt(cur, SOL_SOCKET, SO_ERROR, (char *) &sockerr, &sockerrlen);
}

struct statistics {
    struct io_context *io;
    time_t startup_time;
    time_t start_of_period;
};

/* Do statistics logging */
static void log_statistics(struct statistics *s, int i __attribute__((unused)))
{
    av_ctx *avc = av_new(NULL, NULL);
    io_sched_renew(s->io, s);
    logmsg("STAT: Q=%llu A=%llu R=%llu X=%llu E=%llu B=%d T=%lld "
	   "q=%llu a=%llu r=%llu x=%llu e=%llu b=%d t=%lld",
	   counter_query, counter_answered, counter_retry, counter_expired,
	   counter_err, backlog_max,
	   (long long) (io_now.tv_sec - s->startup_time),
	   counter_p_query, counter_p_answered, counter_p_retry,
	   counter_p_expired, counter_p_err, backlog_max_p, (long long) (io_now.tv_sec - s->start_of_period));

    s->start_of_period = io_now.tv_sec;
    counter_p_query = counter_p_retry = 0;
    counter_p_answered = counter_p_err = 0;
    backlog_max_p = backlog;

    av_clear(avc);
    av_set(avc, AV_A_TYPE, AV_V_TYPE_LOGSTATS);
    mavis_send(mcx, &avc);
    av_free(avc);
}

static void free_payload(void *q)
{
    Xfree(&((struct query *) q)->serial);
    free(q);
}

int main(int argc, char **argv, char **envp)
{
    extern char *optarg;
    extern int optind;
    pid_t pid;
    int c;

    init_common_data();
    common_data.progname = Xstrdup(basename(argv[0]));
    logopen();

    while ((c = getopt(argc, argv, "vPd:")) != EOF)
	switch (c) {
	case 'v':
	    fprintf(stderr, "%s version " VERSION "\n", common_data.progname);
	    exit(EX_OK);
	case 'P':
	    common_data.parse_only = 1;
	    break;
	case 'd':
	    common_data.debug = atoi(optarg);
	    break;
	default:
	    usage();
	}

    if (argc != optind + 1 && argc != optind + 2)
	usage();

    io = io_init();

    logmsg("startup (version " VERSION ")");


    cfg_read_config(argv[optind], parse_decls, argv[optind + 1] ? argv[optind + 1] : common_data.progname);
    if (common_data.parse_only)
	exit(EX_OK);

    setproctitle_init(argv, envp);

    if (background)
	switch (pid = fork()) {
	case 0:
	    mavis_detach();
	    break;
	case -1:
	    logerr("fork (%s:%d)", __FILE__, __LINE__);
	    exit(EX_OSERR);
	default:
	    logmsg("fork() succeeded. New PID is %u.", (u_int) pid);
	    exit(EX_OK);
	}
#ifdef DEBUG
    debug_setpid();
#endif				/* DEBUG */

    if (pidfile && !(common_data.pidfile = pid_write(pidfile)))
	logerr("pid_write(%s) (%s:%d)", pidfile, __FILE__, __LINE__);

    if (stat_period) {
	struct statistics *s = Xcalloc(1, sizeof(struct statistics));
	s->io = io;
	s->startup_time = (time_t) io_now.tv_sec;
	s->start_of_period = (time_t) io_now.tv_sec;

	io_sched_add(io, s, (void *) log_statistics, stat_period, 0);
    }

    mavis_init(mcx, VERSION);

    setproctitle("%s: backlog: %d", common_data.progname, backlog);

    setup_signals();
    setup_sig_segv(common_data.coredumpdir, common_data.gcorepath, common_data.debug_cmd);

    deferred_by_serial = RB_tree_new(compare_crc_serial, free_payload);

    io_main(io);
}
