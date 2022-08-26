/*
 * parse.c
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"
#include <grp.h>

static const char rcsid[] __attribute__((used)) = "$Id$";

int get_request_index(struct service_req *cmds, char *cmd)
{
    static int requests_count = 0, requests_site_count = 0;
    int i, len, mid, start = 0;

    if (!requests_count) {
	struct service_req *c;
	char *s;

	for (s = NULL, c = requests; c->cmd; c++, requests_count++) {
	    if (s && 0 < strcasecmp(s, c->cmd))
		logmsg("Warning! Check request array sort order! " "%s > %s", s, c->cmd);
	    s = c->cmd;
	}
	for (s = NULL, c = requests_site; c->cmd; c++, requests_site_count++) {
	    if (s && 0 < strcasecmp(s, c->cmd))
		logmsg("Warning! Check requests_site array sort order! " "%s > %s", s, c->cmd);
	    s = c->cmd;
	}
    }

    len = (cmds == requests) ? requests_count : requests_site_count;

    do {
	mid = len / 2;
	i = strcasecmp(cmd, cmds[start + mid].cmd);
	if (i < 0)
	    len = mid;
	else if (!i)
	    return start + mid;
	else
	    start += mid, len -= mid;
    }
    while (mid);
    return -1;
}

void checkcmd(struct context *ctx, char *cmd)
{
    int i, do_log = 0;
    static int idx_site = -1, idx_rnto, idx_chmod, idx_pass, idx_noop, idx_mff, idx_mfmt, idx_hash;
    struct service_req *cmds = requests;
    set64 req = ctx->requests, req_dunno = ctx->requests_dunno, req_log = ctx->requests_log;
    struct acl_set **ras = requests_aclset;
    char *cpy = alloca(strlen(cmd) + 1), *arg = NULL, *site = NULL;

    Debug((DEBUG_COMMAND, "+ %s (%s)\n", __func__, cmd));
    strcpy(cpy, cmd);

  try_site:

    i = 0;
    while (*cmd && !isalpha((int) *cmd))
	cmd++;

    if (*cmd) {
	char *t = cmd;
	while (*t && !isspace((int) *t))
	    t++;
	if (*t)
	    arg = t + 1;
	else
	    arg = NULL;
	*t++ = 0;
    }

    i = get_request_index(cmds, cmd);

    if (idx_site < 0) {
	idx_pass = get_request_index(requests, "pass");
	idx_site = get_request_index(requests, "site");
	idx_rnto = get_request_index(requests, "rnto");
	idx_noop = get_request_index(requests, "noop");
	idx_mff = get_request_index(requests, "mff");
	idx_mfmt = get_request_index(requests, "mfmt");
	idx_chmod = get_request_index(requests_site, "chmod");
	idx_hash = get_request_index(requests_site, "hash");
    }

    if (!site && i != idx_rnto)
	ctx->last_command_was_rnfr = 0;

    if (i < 0) {
	reply(ctx, MSG_500_Syntax_cmd_unrec);
	Debug((DEBUG_COMMAND, "- %s (command unrecognized)\n", __func__));
	return;
    }

    if (!SET64_ISSET(i, req)) {
	if (ctx->state == ST_conn)
	    reply(ctx, MSG_530_Not_logged_in);
	else
	    reply(ctx, MSG_502_Command_not_implemented);
	Debug((DEBUG_COMMAND, "- %s (not available)\n", __func__));
	return;
    }

    if (!arg && cmds[i].arg_needed) {
	reply(ctx, MSG_501_Syntax_error_arg_req);
	Debug((DEBUG_COMMAND, "- %s (syntax error)\n", __func__));
	return;
    }

    if (!site && i == idx_site) {
	site = "site ";
	cmds = requests_site;
	req = ctx->requests_site;
	req_log = ctx->requests_site_log;
	req_dunno = ctx->requests_site_dunno;
	ras = requests_site_aclset;
	cmd = arg;
	arg = NULL;
	if (cmd)
	    goto try_site;
    }

    if (SET64_ISSET(i, req_dunno)) {
	int res = 0;
	char *path = NULL;
	if (arg && *arg && cmds[i].buildpath) {
	    char *t = arg;
	    if ((!site && (i == idx_mff || i == idx_mfmt)) || (site && (i == idx_chmod))) {
		for (; *t && !isspace((int) *t); t++);
		for (; *t && isspace((int) *t); t++);
	    }
	    path = buildpath(ctx, t);
	}

	res = eval_ftp_acl(ctx, ras[i]->acl, arg, path);	// S_permit: acl matched

	switch (res) {
	case S_permit:
	    res = (!ras[i]->negate || !ras[i]->permit) ? S_permit : S_deny;
	    break;
	default:
	    res = (ras[i]->negate && !ras[i]->permit) ? S_permit : S_deny;
	    break;
	}

	if (res != S_permit) {
	    if (ctx->state == ST_conn)
		reply(ctx, MSG_530_Not_logged_in);
	    else if (i == idx_hash)
		reply(ctx, MSG_556_Not_hashable);
	    else
		reply(ctx, MSG_504_Command_not_implemented);
	    Debug((DEBUG_COMMAND, "- %s (not for this parameter)\n", __func__));
	    return;
	}
	if (requests_aclset[i]->log)
	    do_log = 1;
    }

    if (cmds[i].changeuid && (current_uid != ctx->uid || current_gid != ctx->gid || update_ids)) {
	seteuid(0);
	setgroups(ctx->gids_size, ctx->gids);
	setegid(ctx->gid);
	seteuid(ctx->uid);
	current_gid = ctx->gid;
	current_uid = ctx->uid;
	update_ids = 0;
    }

    ftp_log(ctx, LOG_COMMAND | ((do_log || SET64_ISSET(i, req_log)) ? LOG_OVERRIDE : 0), (!site && (i == idx_pass)
											  && !ctx->anonymous) ? "PASS ???" : cpy);

    if (i != idx_noop)
	io_sched_renew_proc(ctx->io, ctx, (void *) cleanup);

    cmds[i].handler(ctx, arg);
    DebugOut(DEBUG_COMMAND);
}
