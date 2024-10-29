/*
 * main.c
 *
 * (C)1996-2022 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#define __MAIN__

#include "headers.h"
#include "misc/version.h"
#include <sys/un.h>
#include <grp.h>

#include "misc/sig_segv.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

#ifdef WITH_SSL
#include "misc/ssl_init.h"
#endif				/* WITH_SSL */

static void periodics(struct context *ctx, int cur __attribute__((unused)))
{
    DebugIn(DEBUG_PROC);

    io_sched_renew_proc(ctx->io, ctx, (void *) periodics);
    process_signals();
    io_child_reap();

    struct scm_data sd = {.type = SCM_KEEPALIVE };
    if (!die_when_idle && common_data.scm_send_msg(0, &sd, -1))
	die_when_idle = -1;

    if (common_data.users_cur == 0 && die_when_idle) {
	Debug((DEBUG_PROC, "exiting -- process out of use\n"));
	mavis_drop(mcx);
	logmsg("Terminating, no longer needed.");
	exit(EX_OK);
    }

    DebugOut(DEBUG_PROC);
}

int main(int argc, char **argv, char **envp)
{
    scm_main(argc, argv, envp);

    cfg_init();

    if (!common_data.conffile) {
	common_data.conffile = argv[optind];
	common_data.id = argv[optind + 1];
    }
    if (!common_data.io)
	common_data.io = io_init();
    io = common_data.io;
    cfg_read_config(common_data.conffile, parse_decls, common_data.id ? common_data.id : common_data.progname);

    if (common_data.parse_only)
	exit(EX_OK);

    umask(022);

    acl_finish();

    if (!logformat_transfer)
	logformat_transfer = DEFAULT_LOGFORMAT_TRANSFER;
    if (!logformat_command)
	logformat_command = DEFAULT_LOGFORMAT_COMMAND;
    if (!logformat_event)
	logformat_event = DEFAULT_LOGFORMAT_EVENT;

    logmsg("startup (version " VERSION ")");

    mavis_detach();

    real_uid = getuid();
    real_gid = getgid();
    common_data.pid = getpid();

    srand((u_int) common_data.pid);


#ifdef WITH_SSL
    if (ssl_cert) {
	ssl_ctx = ssl_init(ssl_cert, ssl_key, ssl_pass, ssl_ciphers);
	if (ssl_ctx && ssl_auth)
	    ssl_init_verify(ssl_ctx, ssl_depth, ssl_cafile, ssl_capath);
    }
#endif				/* WITH_SSL */

#ifdef WITH_MMAP
    pagesize = getpagesize();
    bufsize_mmap += pagesize - 1;
    bufsize_mmap /= pagesize;
    bufsize_mmap *= pagesize;
    bufsize += pagesize - 1;
    bufsize /= pagesize;
    bufsize *= pagesize;
#endif				/* WITH_MMAP */

    buffer_setsize(bufsize, 0);
    setup_sig_segv(common_data.coredumpdir, common_data.gcorepath, common_data.debug_cmd);
    setup_sig_bus();

    setgroups(0, NULL);
    umask(0);
    message_init();
    md_init();

    if (common_data.singleprocess) {
	common_data.scm_accept = accept_control_raw;
    } else {
	setproctitle_init(argv, envp);
	setup_signals();
	ctx_spawnd = new_context(io);
	ctx_spawnd->cfn = 0;
	fcntl(ctx_spawnd->cfn, F_SETFL, O_NONBLOCK);
	io_register(io, 0, ctx_spawnd);
	io_set_cb_i(io, 0, (void *) accept_control);
	io_clr_cb_o(io, 0);
	io_set_cb_h(io, 0, (void *) cleanup_spawnd);
	io_set_cb_e(io, 0, (void *) cleanup_spawnd);
	io_set_i(io, 0);
    }

    setup_invalid_callbacks(io);

    struct scm_data sd = {.type = SCM_MAX,.count = (io_get_nfds_limit(common_data.io) - 10) / 4 };
    common_data.scm_send_msg(0, (struct scm_data *) &sd, -1);

    io_sched_add(io, new_context(io), (void *) periodics, 60, 0);

    set_proctitle(ACCEPT_YES);

#ifdef WITH_DNS
    idc = io_dns_init(io);
#endif				/* WITH_DNS */

    mavis_init(mcx, MAVIS_API_VERSION);

    setjmp(sigbus_jmpbuf);

    io_main(io);
}
