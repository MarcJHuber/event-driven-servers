/*
 * h_help.c
 *
 * (C)1998-2022 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"
#include "misc/version.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

void h_site_help(struct context *ctx, char *arg)
{
    struct service_req *cmds = requests_site;

    if (arg && arg[0]) {
	int i = get_request_index(requests_site, arg);
	if (i < 0)
	    replyf(ctx, MSG_502_Unknown_command, arg);
	else if (!SET64_ISSET(i, ctx->requests_site))
	    replyf(ctx, MSG_214_Command_not_implemented, arg);
	else
	    replyf(ctx, MSG_214_Syntax, message[cmds[i].help][ctx->lang]);
    } else {
	int i = 0;
	reply(ctx, MSG_214_supported_SITE_commands);

	for (; cmds->cmd; cmds++, i++)
	    if (cmds->handler && SET64_ISSET(i, ctx->requests_site))
		replyf(ctx, "  %s", cmds->cmd);

	reply(ctx, "\r\n");
	reply(ctx, MSG_214_try_SITE_HELP);
    }
}

void h_help(struct context *ctx, char *arg)
{
    struct service_req *cmds = requests;
    static int idx_site = -1;
#ifdef WITH_SSL
    static int idx_auth = -1;
    static int idx_prot = -1;
    static int idx_pbsz = -1;
#endif

    if (idx_site < 0) {
	idx_site = get_request_index(requests, "site");
#ifdef WITH_SSL
	idx_auth = get_request_index(requests, "auth");
	idx_pbsz = get_request_index(requests, "pbsz");
	idx_prot = get_request_index(requests, "prot");
#endif
    }
#ifdef WITH_SSL
    if (!ssl_ctx) {
	SET64_CLR(idx_auth, ctx->requests);
	SET64_CLR(idx_pbsz, ctx->requests);
	SET64_CLR(idx_prot, ctx->requests);
    }
#endif

    if (arg && arg[0]) {
	int i = get_request_index(requests, arg);

	if (i < 0)
	    replyf(ctx, MSG_502_Unknown_command, arg);
	else if (!SET64_ISSET(i, ctx->requests))
	    replyf(ctx, MSG_214_Command_not_implemented, arg);
	else if (i == idx_site)
	    h_site_help(ctx, NULL);
	else
	    replyf(ctx, MSG_214_Syntax, message[cmds[i].help][ctx->lang]);
    } else {
	int count = 0, i = 0;
	reply(ctx, "214-\r\n");
	if (!hide_version)
	    replyf(ctx, "  %s, version " VERSION " (compiled: " __DATE__ " " __TIME__ ")\r\n", common_data.progname);
	else
	    replyf(ctx, "  %s", common_data.progname);
	reply(ctx, "  (C)1996-2022 by Marc Huber <Marc.Huber@web.de>\r\n");
	reply(ctx, "\r\n");

	reply(ctx, MSG_Supported_commands);

	for (; cmds->cmd; cmds++, i++)
	    if (SET64_ISSET(i, ctx->requests)) {
		replyf(ctx, "  %-4s", cmds->cmd);
		if (!(++count % 12))
		    reply(ctx, "\r\n");
	    }

	if (count % 12)
	    reply(ctx, "\r\n");
	reply(ctx, "\r\n");

	if (ctx->maintainer)
	    replyf(ctx, MSG_214_Direct_comments, ctx->maintainer);
	else
	    reply(ctx, MSG_214_Thats_all);
    }
}
