/*
 * spawnd_main.c
 * (C)2000-2011 by Marc Huber <Marc.Huber@web.de>
 *
 * $Id$
 *
 */

#define __MAIN__

#include "spawnd_headers.h"
#include "misc/version.h"
#include "misc/sig_segv.h"
#include "misc/pid_write.h"
#include <signal.h>
#include <sysexits.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif
#ifdef __FreeBSD__
#include <sys/sysctl.h>
#endif

static const char rcsid[] __attribute__((used)) = "$Id$";

struct spawnd_data spawnd_data = { 0 };	/* configuration data */

static void periodics(struct spawnd_context *ctx, int cur __attribute__((unused)))
{
    pid_t deadpid = -1;
    int status, i;

    DebugIn(DEBUG_PROC);

    io_sched_renew(ctx->io, ctx);

    while (0 < (deadpid = waitpid(-1, &status, WNOHANG))) {
	int sig = 0;

	if (!WIFEXITED(status) && WIFSIGNALED(status))
	    sig = WTERMSIG(status);

	for (i = 0; i < common_data.servers_cur && spawnd_data.server_arr[i]->pid != deadpid; i++);

	if (sig)
	    logmsg("child (pid %u) terminated abnormally (signal %d)", (u_int) deadpid, sig);
	else
	    logmsg("child (pid %u) terminated normally", (u_int) deadpid);

	if (i < common_data.servers_cur)
	    spawnd_cleanup_internal(spawnd_data.server_arr[i], spawnd_data.server_arr[i]->fn);
    }

    if (spawnd_data.abandon) {
	spawnd_data.abandon = 0;
	while (common_data.servers_cur)
	    spawnd_cleanup_internal(spawnd_data.server_arr[0], spawnd_data.server_arr[0]->fn);
    }

    if (io_now.tv_sec & 7) {
	DebugOut(DEBUG_PROC);
	return;
    }

    spawnd_process_signals();

    if (common_data.users_cur < (common_data.users_min * (common_data.servers_cur + 1))) {
	int servers_count = common_data.servers_cur;
	for (i = 0; i < common_data.servers_cur; i++)
	    if (spawnd_data.server_arr[i]->dying)
		servers_count--;

	Debug((DEBUG_PROC, "servers_cur: %d\n", common_data.servers_cur));
	Debug((DEBUG_PROC, "servers_count: %d\n", servers_count));
	Debug((DEBUG_PROC, "servers_min: %d\n", common_data.servers_min));

	for (i = 0; i < common_data.servers_cur && servers_count > common_data.servers_min; i++)
	    if (!spawnd_data.server_arr[i]->use) {
		if (!spawnd_data.server_arr[i]->dying) {
		    struct scm_data sd = {.type = SCM_MAY_DIE };
		    spawnd_data.server_arr[i]->dying = 1;
		    Debug((DEBUG_PROC, "server %d may die\n", i));
		    common_data.scm_send_msg(spawnd_data.server_arr[i]->fn, &sd, -1);
		}
		servers_count--;
	    }
    }
    DebugOut(DEBUG_PROC);
}

void get_exec_path(char **path, char *dflt)
{
    char tmp[PATH_MAX];
    ssize_t rls;

    if (strchr(dflt, '/')) {
	*path = strdup(dflt);
	return;
    }
#if defined(CTL_KERN) && defined(KERN_PROC) && defined(KERN_PROC_PATHNAME)
    {
	size_t size = sizeof(tmp);
	int mib[4];
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PATHNAME;
	mib[3] = -1;
	if (!sysctl(mib, 4, tmp, &size, NULL, 0)) {
	    *path = strdup(tmp);
	    return;
	}
    }
#endif

#if defined(__APPLE__)
    {
	uint32_t size = sizeof(tmp);
	if (!_NSGetExecutablePath(tmp, &size)) {
	    *path = strdup(tmp);
	    return;
	}
    }
#endif

#if defined(__sun__)
    {
	char *p = (char *) getexecname();
	if (p) {
	    *path = strdup(p);
	    return;
	}
    }
#endif

    rls = readlink("/proc/self/exe", tmp, sizeof(tmp));
    if (rls < 0)
	rls = readlink("/proc/curproc/file", tmp, sizeof(tmp));
    if (rls < 0) {
	char ptmp[PATH_MAX];
	snprintf(ptmp, sizeof(ptmp), "/proc/%lu/exe", (u_long) getpid());
	rls = readlink(ptmp, tmp, sizeof(tmp));
    }
    if (rls > 0) {
	tmp[rls] = 0;
	*path = strdup(tmp);
	return;
    }

    *path = strdup(dflt);
}

static char **dup_array(char **a)
{
    int i;
    char **v;

    v = a, i = 0;
    while (*v)
	v++, i++;

    v = calloc(++i, sizeof(char *));

    i = 0;
    while (*a) {
	v[i] = strdup(*a);
	a++, i++;
    }

    return v;
}

struct spawnd_context *spawnd_new_context(struct io_context *io)
{
    struct spawnd_context *c = Xcalloc(1, sizeof(struct spawnd_context));
    c->io = io;
    c->fn = -1;
    c->keepintvl = -1;
    c->keepcnt = -1;
    c->keepidle = -1;

    return c;
}

int spawnd_note_listener(sockaddr_union *sa __attribute__((unused)), void *data)
{
    spawnd_data.listener_arr = Xrealloc(spawnd_data.listener_arr, (spawnd_data.listeners_max + 1) * sizeof(struct spawnd_context *));
    spawnd_data.listener_arr[spawnd_data.listeners_max] = (struct spawnd_context *) data;
    memcpy(&spawnd_data.listener_arr[spawnd_data.listeners_max++]->sa, sa, sizeof(sockaddr_union));
    return 0;
}

void spawnd_bind_listener(struct spawnd_context *ctx, int cur)
{
    char buf[INET6_ADDRSTRLEN];

    DebugIn(DEBUG_NET);
    if (ctx->fn < 0) {
	io_sched_del(common_data.io, ctx, (void *) spawnd_bind_listener);

	cur = su_socket(ctx->sa.sa.sa_family, ctx->socktype, ctx->protocol);
#if defined(IP_PKTINFO) || defined(IPV6_PKTINFO)
	if (ctx->socktype == SOCK_DGRAM) {
	    int one = 1;
#ifdef IP_PKTINFO
	    setsockopt(cur, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one));
#endif
#ifdef IPV6_PKTINFO
	    setsockopt(cur, IPPROTO_IP, IPV6_PKTINFO, &one, sizeof(one));
#endif
	}
#endif
	fcntl(cur, F_SETFD, fcntl(cur, F_GETFD, 0) | FD_CLOEXEC);

	if (cur < 0) {
	    logerr("socket(%d, %d, %d) [%s:%d]", ctx->sa.sa.sa_family, ctx->socktype, ctx->protocol, __FILE__, __LINE__);
	    if (ctx->retry_delay)
		io_sched_add(common_data.io, ctx, (void *) spawnd_bind_listener, (time_t) ctx->retry_delay, (suseconds_t) 0);
	    DebugOut(DEBUG_NET);
	    return;
	}
#ifdef AF_UNIX
	if (ctx->sa.sa.sa_family == AF_UNIX)
	    unlink(ctx->sa.sun.sun_path);
#endif				/* AF_UNIX */

#ifdef VRF_BINDTODEVICE
	if (ctx->vrf && (ctx->sa.sa.sa_family == AF_INET || ctx->sa.sa.sa_family == AF_INET6)) {
	    if (setsockopt(cur, SOL_SOCKET, SO_BINDTODEVICE, ctx->vrf, ctx->vrf_len))
		logerr("setsockopt failed to set the VRF to \"%s\" [%s:%d]", ctx->vrf, __FILE__, __LINE__);
	}
#endif
#if defined(VRF_RTABLE) || defined(VRF_SETFIB)
	if (ctx->vrf_id > -1 && (ctx->sa.sa.sa_family == AF_INET || ctx->sa.sa.sa_family == AF_INET6)) {
	    unsigned int opt = (unsigned int) ctx->vrf_id;
	    socklen_t optlen = sizeof(opt);
	    if (setsockopt(cur, SOL_SOCKET,
#ifdef VRF_RTABLE
			   SO_RTABLE
#endif
#ifdef VRF_SETFIB
			   SO_SETFIB
#endif
			   , &opt, optlen))
		logerr("setsockopt failed to set the VRF to \"%d\" [%s:%d]", ctx->vrf_id, __FILE__, __LINE__);
	}
#endif
#ifdef SO_REUSEPORT
	if (ctx->protocol == IPPROTO_UDP) {
	    int one = 1;
	    setsockopt(cur, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
	}
#endif
	ctx->port = su_get_port(&ctx->sa);
	if (su_bind(cur, &ctx->sa)) {
	    if (!ctx->logged_retry)
		logerr("bind (%s:%d)", __FILE__, __LINE__);
#ifdef AF_UNIX
	    if (ctx->sa.sa.sa_family == AF_UNIX) {
		if (!ctx->logged_retry) {
		    ctx->logged_retry = 1;
		    if (ctx->retry_delay)
			logmsg("bind to %s failed. Will retry every %d seconds.", ctx->sa.sun.sun_path, ctx->retry_delay);
		    else
			logmsg("bind to %s failed.", ctx->sa.sun.sun_path);
		}
	    } else
#endif
	    if (!ctx->logged_retry) {
		ctx->logged_retry = 1;
		if (ctx->retry_delay)
		    logmsg
			("bind to [%s]:%d failed. Will retry every %d seconds.",
			 su_ntop(&ctx->sa, buf, (socklen_t) sizeof(buf)), su_get_port(&ctx->sa), ctx->retry_delay);
		else
		    logmsg("bind to [%s]:%d failed.", su_ntop(&ctx->sa, buf, (socklen_t) sizeof(buf)), su_get_port(&ctx->sa));
	    }
	    if (ctx->retry_delay)
		io_sched_add(common_data.io, ctx, (void *) spawnd_bind_listener, (time_t) ctx->retry_delay, (suseconds_t) 0);
	    else {
		spawnd_data.bind_failures++;
		if (spawnd_data.bind_failures == spawnd_data.listeners_max) {
		    logmsg("Failed to bind to any address or port. Exiting.");
		    exit(EX_TEMPFAIL);
		}
	    }

	    Debug((DEBUG_NET, "- %s (bind error)\n", __func__));
	    close(cur);
	    return;
	}

	ctx->fn = cur;

#ifdef AF_UNIX
	if (ctx->sa.sa.sa_family == AF_UNIX) {
	    if (chown(ctx->sa.sun.sun_path, ctx->uid, ctx->gid))
		logerr("chown(%s) (%s:%d)", ctx->sa.sun.sun_path, __FILE__, __LINE__);

	    if (ctx->mode)
		if (chmod(ctx->sa.sun.sun_path, ctx->mode)) {
		    logerr("chmod(%s) (%s:%d)", ctx->sa.sun.sun_path, __FILE__, __LINE__);
		}
	}
#endif				/* AF_UNIX */
    }

    logmsg("bind to [%s]:%d succeeded%s", su_ntop(&ctx->sa, buf, (socklen_t) sizeof(buf)), su_get_port(&ctx->sa), ctx->fn ? "" : " (via inetd)");

    if (ctx->socktype != SOCK_DGRAM && listen(ctx->fn, ctx->listen_backlog)) {
	logerr("listen (%s:%d)", __FILE__, __LINE__);
	Debug((DEBUG_NET, "- %s (listen error)\n", __func__));
	return;
    }

    ctx->is_listener = 1;

    ctx->io = common_data.io;
    io_register(common_data.io, ctx->fn, ctx);
    io_set_cb_i(common_data.io, ctx->fn, (void *) spawnd_accepted);
    io_clr_cb_o(common_data.io, ctx->fn);
    io_set_cb_e(common_data.io, ctx->fn, (void *) spawnd_cleanup_internal);
    io_set_cb_h(common_data.io, ctx->fn, (void *) spawnd_cleanup_internal);
    io_set_i(common_data.io, ctx->fn);

    DebugOut(DEBUG_NET);
}

int spawnd_main(int argc, char **argv, char **envp, char *id)
{
    extern char *optarg;
    extern int optind;
    pid_t pid;
    int c, devnull, i;
    struct spawnd_context *ctx = NULL;
    int socktype = 0;
    socklen_t socktypelen = sizeof(socktype);

    init_common_data();
    common_data.argv = dup_array(argv);
    common_data.envp = dup_array(envp);
    common_data.users_min = 20;
    common_data.users_max = 60;
    common_data.servers_min = 2;
    common_data.servers_max = 8;
    common_data.progname = Xstrdup(basename(argv[0]));
    common_data.version = VERSION
#ifdef WITH_PCRE2
	"/PCRE2"
#endif
#ifdef WITH_CRYPTO
	"/CRYPTO"
#endif
#ifdef WITH_ARES
	"/ARES"
#endif
#ifdef WITH_CURL
	"/CURL"
#endif
#ifdef WITH_TLS
	"/TLS"
#endif
#ifdef WITH_SSL
	"/SSL"
#endif
#ifdef DEBUG
	"/DEBUG"
#endif
	;
    logopen();

    get_exec_path(&spawnd_data.child_path, argv[0]);
    spawnd_data.overload = S_queue;
    common_data.progpath = Xstrdup(spawnd_data.child_path);
    spawnd_data.keepintvl = -1;
    spawnd_data.keepcnt = -1;
    spawnd_data.keepidle = -1;
    spawnd_data.scm_bufsize = 0;	// leave at system default
    spawnd_data.abandon = 0;
    spawnd_data.track_data.tracking_size = 1024;

    if (!getsockopt(0, SOL_SOCKET, SO_TYPE, &socktype, &socktypelen))
	switch (socktype) {
	case SOCK_DGRAM:
	    logmsg("FATAL: Recursive execution prohibited.");
	    scm_fatal();
	case SOCK_STREAM:
	    spawnd_data.inetd = 1;
	}

    while ((c = getopt(argc, argv, "vPd:i:p:bf1I:")) != EOF)
	switch (c) {
	case 'v':
	    common_data.version_only = 1;
	    break;
	case 'P':
	    common_data.parse_only = 1;
	    break;
	case 'd':
	    common_data.debug = atoi(optarg) & DEBUG_ALL_FLAG;
	    break;
	case 'b':
	    spawnd_data.background = 1;
	    spawnd_data.background_lock = 1;
	    break;
	case 'f':
	    spawnd_data.background = 0;
	    spawnd_data.background_lock = 1;
	    break;
	case 'i':
	    strset(&spawnd_data.child_id, optarg);
	    break;
	case 'I':
	    id = optarg;
	    break;
	case 'p':
	    strset(&spawnd_data.pidfile, optarg);
	    spawnd_data.pidfile_lock = 1;
	    break;
	case '1':
	    common_data.singleprocess = 1;
	    break;
	default:
	    common_usage();
	}

    if (argc == optind && common_data.version_only) {
	int status;
	spawnd_spawn_child(NULL);
	waitpid(-1, &status, 0);
	exit(WEXITSTATUS(status));
    }

    if (argc != optind + 1 && argc != optind + 2)
	common_usage();

    strset(&spawnd_data.child_config, argv[optind]);

    common_data.conffile = Xstrdup(argv[optind]);
    if (argv[optind + 1])
	common_data.id = Xstrdup(argv[optind + 1]);

    logmsg("startup%s (version " VERSION ")", spawnd_data.inetd ? " via inetd" : "");

    umask(077);

    if (spawnd_data.inetd) {
	int one = 1;
	socklen_t sulen = sizeof(sockaddr_union);
	ctx = spawnd_new_context(NULL);
	ctx->fn = 0;
	ctx->listen_backlog = 128;
	setsockopt(0, SOL_SOCKET, SO_REUSEADDR, (char *) &one, (socklen_t) sizeof(one));
	fcntl(ctx->fn, F_SETFD, fcntl(ctx->fn, F_GETFD, 0) | FD_CLOEXEC);
	fcntl(ctx->fn, F_SETFL, O_NONBLOCK);
	if (0 > getsockname(0, &ctx->sa.sa, &sulen)) {
	    logerr("getsockname (%s:%d)", __FILE__, __LINE__);
	} else {
	    spawnd_data.listener_arr = Xrealloc(spawnd_data.listener_arr, (spawnd_data.listeners_max + 1) * sizeof(struct spawnd_context *));
	    spawnd_data.listener_arr[spawnd_data.listeners_max++] = ctx;
	}
	spawnd_data.background = 0;
	spawnd_data.background_lock = 1;
    }

    spawnd_data.retry_delay = 0;

    common_data.conffile = strdup(argv[optind]);
    if (argv[optind + 1])
	common_data.id = strdup(argv[optind + 1]);

    cfg_read_config(argv[optind], spawnd_parse_decls, id ? id : (argv[optind + 1] ? argv[optind + 1] : common_data.progname));

    common_data.users_max_total = common_data.users_max * common_data.servers_max;

    if (common_data.servers_max < common_data.servers_min)
	common_data.servers_min = common_data.servers_max;

    switch (spawnd_data.overload) {
    case S_reset:
	spawnd_data.overload_hint = "resetting";
	break;
    case S_close:
	spawnd_data.overload_hint = "immediately closing";
	break;
    default:
	spawnd_data.overload_hint = "queueing";
    }

    if (common_data.parse_only || common_data.version_only) {
	int status;
	spawnd_spawn_child(NULL);
	waitpid(-1, &status, 0);
	exit(WEXITSTATUS(status));
    }

    setproctitle_init(argv, envp);

    umask(022);

    if (!spawnd_data.listeners_max) {
	logmsg("FATAL: No listeners defined.");
	exit(EX_OSERR);
    }

    if (spawnd_data.background)
	switch (pid = fork()) {
	case 0:
	    devnull = open("/dev/null", O_RDWR);
	    dup2(devnull, 0);
	    dup2(devnull, 1);
	    if (!common_data.debug_redirected)
		dup2(devnull, 2);
	    close(devnull);
	    setsid();
	    break;
	case -1:
	    logerr("fork (%s:%d)", __FILE__, __LINE__);
	    exit(EX_OSERR);
	default:
	    // logmsg("fork() succeeded. New PID is %u.", (u_int) pid);
	    exit(EX_OK);
	}
#ifdef DEBUG
    debug_setpid();
#endif				/* DEBUG */

    if (spawnd_data.pidfile && !(common_data.pidfile = pid_write(spawnd_data.pidfile)))
	logerr("pid_write(%s) (%s:%d)", spawnd_data.pidfile, __FILE__, __LINE__);

    common_data.io = io_init();

    for (i = 0; i < spawnd_data.listeners_max; i++) {
	if (spawnd_data.listener_arr[i]->keepcnt < 0)
	    spawnd_data.listener_arr[i]->keepcnt = spawnd_data.keepcnt;
	if (spawnd_data.listener_arr[i]->keepidle < 0)
	    spawnd_data.listener_arr[i]->keepidle = spawnd_data.keepidle;
	if (spawnd_data.listener_arr[i]->keepintvl < 0)
	    spawnd_data.listener_arr[i]->keepintvl = spawnd_data.keepintvl;

	spawnd_data.listener_arr[i]->io = common_data.io;
	spawnd_bind_listener(spawnd_data.listener_arr[i], spawnd_data.listener_arr[i]->fn);
    }

#ifdef BROKEN_FD_PASSING
    common_data.singleprocess = 1;
#endif

    if (common_data.singleprocess) {
	logmsg("Warning: Running in degraded mode. This is unsuitable for real-life usage.");
	common_data.servers_min = 1;
	common_data.servers_max = 1;
	common_data.scm_send_msg = fakescm_send_msg;
	common_data.scm_recv_msg = fakescm_recv_msg;
	return 0;
    }

    ctx = spawnd_new_context(common_data.io);
    io_sched_add(common_data.io, ctx, (void *) periodics, (time_t) 1, (suseconds_t) 0);

    spawnd_data.server_arr = Xcalloc(common_data.servers_max, sizeof(struct spawnd_context *));

    spawnd_setup_signals();
    setup_sig_segv(common_data.coredumpdir, common_data.gcorepath, common_data.debug_cmd);

    while (common_data.servers_cur < common_data.servers_min)
	spawnd_add_child();

    set_proctitle(ACCEPT);

    io_main(common_data.io);
}

void scm_main(int argc, char **argv, char **envp)
{
    extern char *optarg;
    extern int optind;
    int socktype = 0, c;
    socklen_t socktypelen = (socklen_t) sizeof(socktype);

    init_common_data();
    common_data.progname = strdup(basename(argv[0]));

    common_data.version = VERSION
#ifdef WITH_PCRE2
	"/PCRE2"
#endif
#ifdef WITH_CRYPTO
	"/CRYPTO"
#endif
#ifdef WITH_ARES
	"/ARES"
#endif
#ifdef WITH_CURL
	"/CURL"
#endif
#ifdef WITH_TLS
	"/TLS"
#endif
#ifdef WITH_SSL
	"/SSL"
#endif
	;
    logopen();

    if (getsockopt(0, SOL_SOCKET, SO_TYPE, &socktype, &socktypelen)
	|| socktype != SOCK_DGRAM) {
	spawnd_main(argc, argv, envp, "spawnd");
	if (common_data.singleprocess)
	    return;
	exit(0);
    }

    while ((c = getopt(argc, argv, "vPd:")) != EOF)
	switch (c) {
	case 'v':
	    fprintf(stderr, "%s version %s\n", common_data.progname, common_data.version);
	    exit(EX_OK);
	case 'P':
	    common_data.parse_only = 1;
	    break;
	case 'd':{
		int i = atoi(optarg);
		if (i == DEBUG_TACTRACE_FLAG)
		    common_data.debug |= i;
		else
		    common_data.debug |= (i & DEBUG_ALL_FLAG);
		break;
	    }
	default:
	    common_usage();
	}
    if (argc != optind + 1 && argc != optind + 2)
	common_usage();
}
