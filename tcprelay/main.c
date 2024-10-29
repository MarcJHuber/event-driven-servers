/*
 * main.c
 * (C)1999-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#define __MAIN__

#include "misc/sysconf.h"
#include "headers.h"
#include "misc/version.h"
#include "misc/sig_segv.h"
#include <sys/un.h>

static const char rcsid[] __attribute__((used)) = "$Id$";

#ifdef WITH_TLS
#else
#ifdef WITH_SSL
#include "misc/ssl_init.h"
#endif				/* WITH_SSL */
#endif

static void periodics(struct context *ctx, int cur __attribute__((unused)))
{
    DebugIn(DEBUG_PROC);

    io_sched_renew(ctx->io, ctx);
    process_signals();		/* process pending signals */

    struct scm_data sd = {.type = SCM_KEEPALIVE };
    if (!die_when_idle && common_data.scm_send_msg(0, &sd, -1))
	die_when_idle = -1;

    if (common_data.users_cur == 0 && die_when_idle) {
	Debug((DEBUG_PROC, "exiting -- process out of use\n"));
	logmsg("Terminating, no longer needed.");
	exit(EX_OK);
    }

    DebugOut(DEBUG_PROC);
}

int main(int argc, char **argv, char **envp)
{
    struct io_context *io;

    scm_main(argc, argv, envp);

    if (!common_data.conffile) {
	common_data.conffile = argv[optind];
	common_data.id = argv[optind + 1];
    }
    cfg_read_config(common_data.conffile, parse_decls, common_data.id ? common_data.id : common_data.progname);

    if (common_data.parse_only)
	exit(EX_OK);

    umask(022);

    if (!con_arr) {
	logmsg("No remote services defined! Exiting.");
	exit(EX_USAGE);
    }

    logmsg("startup (version " VERSION ")");

    mavis_detach();

#ifdef WITH_TLS
    if (ssl_cert) {
	struct tls_config *cfg = NULL;
	uint8_t *p;
	size_t p_len;
	if (tls_init()) {
	    logerr("tls_init");
	    exit(EX_CONFIG);
	}
	cfg = tls_config_new();
	if (!cfg) {
	    logerr("tls_cconfig_new");
	    exit(EX_CONFIG);
	}
	p = tls_load_file(ssl_cert, &p_len, NULL);
	if (!p) {
	    logerr("tls_load_file (%d): %s", __LINE__, ssl_cert);
	    exit(EX_CONFIG);
	}
	if (tls_config_set_cert_mem(cfg, p, p_len)) {
	    logerr("tls_config_set_cert_mem");
	    exit(EX_CONFIG);
	}
	p = tls_load_file(ssl_key, &p_len, ssl_pass);
	if (!p) {
	    logerr("tls_load_file (%d): %s", __LINE__, ssl_key);
	    exit(EX_CONFIG);
	}
	if (tls_config_set_key_mem(cfg, p, p_len)) {
	    logerr("tls_config_set_key_mem");
	    exit(EX_CONFIG);
	}
	ssl_ctx = tls_server();
	if (!ssl_ctx) {
	    logerr("tls_ctx");
	    exit(EX_CONFIG);
	}
	if (tls_configure(ssl_ctx, cfg)) {
	    logerr("tls_configure");
	    exit(EX_CONFIG);
	}
    }
#else
#ifdef WITH_SSL
    if (ssl_cert)
	ssl_ctx = ssl_init(ssl_cert, ssl_key, ssl_pass, NULL);
#endif				/* WITH_SSL */
#endif

    setup_sig_segv(common_data.coredumpdir, common_data.gcorepath, common_data.debug_cmd);

    if (common_data.singleprocess) {
	common_data.scm_accept = accepted_raw;
	io = common_data.io;
    } else {
	setproctitle_init(argv, envp);
	io = common_data.io = io_init();
	setup_signals();
	ctx_spawnd = new_context(io);
	ctx_spawnd->ifn = 0;
	io_register(io, 0, ctx_spawnd);
	io_set_cb_i(io, 0, (void *) accepted);
	io_set_cb_e(io, 0, (void *) cleanup_spawnd);
	io_set_cb_h(io, 0, (void *) cleanup_spawnd);
	io_set_i(io, 0);
	fcntl(0, O_NONBLOCK);
    }

    struct scm_data sd = {.type = SCM_MAX,.count = (io_get_nfds_limit(common_data.io) - 10) / 2 };
    common_data.scm_send_msg(0, (struct scm_data *) &sd, -1);
    io_sched_add(io, new_context(io), (void *) periodics, 60, 0);

    set_proctitle(ACCEPT_YES);

    io_main(io);
}
