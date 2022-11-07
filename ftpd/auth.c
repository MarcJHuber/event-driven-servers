/*
 * auth.c
 *
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"
#include "mavis/groups.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

static void auth_mavis_sync(struct context *, av_ctx *);

static void set_out_c(struct context *ctx, int cur __attribute__((unused)))
{
    Debug((DEBUG_PROC, "set_out_c(%d)\n", ctx->cfn));
    io_sched_pop(ctx->io, ctx);
    if (ctx && ctx->cfn > -1)
	io_set_o(ctx->io, ctx->cfn);
}

void auth_mavis_callback(struct context *ctx)
{
    av_ctx *avc = NULL;
    DebugIn(DEBUG_PROC);
    switch (mavis_recv(mcx, &avc, ctx)) {
    case MAVIS_FINAL:
	ctx->auth_in_progress = 0;
	auth_mavis_sync(ctx, avc);
	break;
    case MAVIS_TIMEOUT:
	ctx->auth_in_progress = 0;
	logmsg("auth_mavis: giving up (%s)", ctx->user);
	io_sched_pop(ctx->io, ctx);
	ctx->state = ST_conn;
	reply(ctx, MSG_550_No_response_from_auth);
	break;
    case MAVIS_DEFERRED:
    case MAVIS_IGNORE:
	break;
    default:
	ctx->auth_in_progress = 0;
	logmsg("auth_mavis: internal error (%s:%d)", __FILE__, __LINE__);
	reply(ctx, MSG_551_Internal_error);
	ctx->state = ST_conn;
    }

    DebugOut(DEBUG_PROC);
}

void auth_mavis(struct context *ctx, char *pass)
{
    char buf[INET6_ADDRSTRLEN];
    av_ctx *avc;

    DebugIn(DEBUG_PROC);

    ctx->state = ST_asyncauth;

    if (ctx->authfailures_bye && ctx->authfailures >= ctx->authfailures_bye) {
	reply(ctx, MSG_421_Service_not_available);
	io_clr_i(ctx->io, ctx->cfn);
	io_clr_cb_i(ctx->io, ctx->cfn);
	logmsg("ERR|%.8lx|%s: Too many authentication failures (%d), " "closing connection", ctx->id, ctx->user, ctx->authfailures);
	Debug((DEBUG_PROC, "- %s: Far too many authentication failures\n", __func__));
	return;
    }

    if (ctx->authfailures_max && ctx->authfailures >= ctx->authfailures_max) {
	ctx->authfailures++;
	reply(ctx, MSG_530_Login_incorrect);
	io_clr_o(ctx->io, ctx->cfn);
	io_sched_add(ctx->io, ctx, (void *) set_out_c, ctx->authfailures, 0);
	logmsg("ERR|%.8lx|%s: Too many authentication failures (%d), " "ignoring subsequent attempts", ctx->id, ctx->user, ctx->authfailures);
	Debug((DEBUG_PROC, "- %s: Too many authentication failures\n", __func__));
	return;
    }

    avc = av_new((void *) auth_mavis_callback, (void *) ctx);
    av_set(avc, AV_A_TYPE, AV_V_TYPE_FTP);

    if (ctx->vhost)
	av_set(avc, AV_A_VHOST, ctx->vhost);
    else if (ctx->hostname)
	av_set(avc, AV_A_VHOST, ctx->hostname);

    av_set(avc, AV_A_USER, ctx->user);
    av_set(avc, AV_A_PASSWORD, pass);
    av_set(avc, AV_A_IPADDR, su_ntop(&ctx->sa_c_remote, buf, (socklen_t) sizeof(buf)));
    av_set(avc, AV_A_SERVERIP, su_ntop(&ctx->sa_c_local, buf, (socklen_t) sizeof(buf)));

#ifdef WITH_SSL
    if (ctx->certsubj)
	av_set(avc, AV_A_CERTSUBJ, ctx->certsubj);
#endif

    switch (mavis_send(mcx, &avc)) {
    case MAVIS_FINAL:
	ctx->auth_in_progress = 0;
	auth_mavis_sync(ctx, avc);
	break;
    case MAVIS_TIMEOUT:
	ctx->auth_in_progress = 0;
	logmsg("auth_mavis: giving up (%s)", ctx->user);
	io_sched_pop(ctx->io, ctx);
	ctx->state = ST_conn;
	reply(ctx, MSG_550_No_response_from_auth);
	break;
    case MAVIS_DEFERRED:
	ctx->auth_in_progress = 1;
	break;
    default:
	ctx->auth_in_progress = 0;
	logmsg("auth_mavis: internal error (%s:%d)", __FILE__, __LINE__);
	reply(ctx, MSG_551_Internal_error);
	ctx->state = ST_conn;
    }

    DebugOut(DEBUG_PROC);
}

static void auth_mavis_sync(struct context *ctx, av_ctx * avc)
{
    char *r = NULL, *t, *u, *hd, *cwd;
    struct stat st;
    int i;

    DebugIn(DEBUG_PROC);

    ctx->state = ST_user;

    if ((t = av_get(avc, AV_A_TYPE)) && !strcmp(t, AV_V_TYPE_FTP) &&
	ctx->user &&
	(t = av_get(avc, AV_A_USER)) && !strcmp(t, ctx->user) &&
	(r = av_get(avc, AV_A_RESULT)) && !strcmp(r, AV_V_RESULT_OK) &&
	(t = av_get(avc, AV_A_UID)) &&
	(ctx->uid = (uid_t) strtoul(t, NULL, 10)) &&
	(t = av_get(avc, AV_A_GID)) &&
	(ctx->gid = (gid_t) strtoul(t, NULL, 10)) && (cwd = av_get(avc, AV_A_HOME)) && (u = av_get(avc, AV_A_ROOT)) && (strlen(u) < sizeof(ctx->root)))
	strcpy(ctx->root, u);
    else {
	if (r) {
	    char *er = av_get(avc, AV_A_USER_RESPONSE);
	    ctx->state = ST_conn;
	    ctx->authfailures++;
	    if (er)
		/* XXX ... this is obviously not LANG compliant */
		replyf(ctx, "530 %s\r\n", er);
	    else
		reply(ctx, MSG_530_Login_incorrect);
	    io_clr_o(ctx->io, ctx->cfn);
	    io_sched_add(ctx->io, ctx, (void *) set_out_c, ctx->authfailures, 0);
	}
	Debug((DEBUG_PROC, "- %s: incomplete or invalid\n", __func__));
	av_free(avc);
	return;
    }

    Debug((DEBUG_PROC, "  uid: %u gid: %u\n", (u_int) ctx->uid, (u_int) ctx->gid));

    if ((t = av_get(avc, AV_A_QUOTA_LIMIT)))
	ctx->quota_limit = strtol(t, NULL, 10);

    if ((t = av_get(avc, AV_A_QUOTA_PATH)))
	ctx->quota_path = Xstrdup(t);

    ctx->anonymous = (t = av_get(avc, AV_A_FTP_ANONYMOUS)) && !strcmp(t, AV_V_BOOL_TRUE);

    if ((t = av_get(avc, AV_A_TRAFFICSHAPING)))
	ctx->shape_bandwidth = strtoul(t, NULL, 10);

    if ((t = av_get(avc, AV_A_ANON_INCOMING))) {
	if (ctx->incoming)
	    regfree(ctx->incoming);
	else
	    ctx->incoming = Xcalloc(1, sizeof(regex_t));
	if (regcomp(ctx->incoming, t, REG_EXTENDED | common_data.regex_posix_flags | REG_NOSUB))
	    logerr("regcomp(%s) failed", t);
    }

    if ((t = av_get(avc, AV_A_GIDS)))
	groups_ascii2list(t, &(ctx->gids_size), ctx->gids);

    if ((t = av_get(avc, AV_A_UMASK))
	&& (1 == sscanf(t, "%o", &ctx->umask)))
	ctx->umask_set = 1;

    ctx->rootlen = (u_int) strlen(ctx->root);

    /* make sure that the root path doesn't end with a /, or pretty weird
       things may happen later on ... */

    for (i = ctx->rootlen - 1; i > -1 && ctx->root[i] == '/'; i--)
	ctx->rootlen = i, ctx->root[i] = 0;

    if (current_uid != ctx->uid || current_gid != ctx->gid) {
	UNUSED_RESULT(seteuid(0));
	setgroups(ctx->gids_size, ctx->gids);
	UNUSED_RESULT(setegid(ctx->gid));
	UNUSED_RESULT(seteuid(ctx->uid));
	current_gid = ctx->gid;
	current_uid = ctx->uid;
    }

    if (chdir(ctx->rootlen ? ctx->root : "/") || stat(".", &st)) {
	logerr("chdir/stat: %s (%s)", ctx->rootlen ? ctx->root : "/", ctx->user);
	reply(ctx, MSG_550_No_access_to_rootdir);
	ctx->state = ST_conn;
	av_free(avc);
	DebugOut(DEBUG_PROC);
	return;
    }

    ctx->root_dev = st.st_dev, ctx->root_ino = st.st_ino;

    hd = buildpath(ctx, cwd);
    if (!hd || (ctx->cwdlen = (u_int) strlen(hd)) >= sizeof(ctx->cwd)) {
	logerr("buffer too small in %s:%d (%s/%s)", __FILE__, __LINE__, ctx->user, hd);
	reply(ctx, MSG_551_Internal_error);
	ctx->state = ST_conn;
	av_free(avc);
	DebugOut(DEBUG_PROC);
	return;
    }

    if (hd[0] == '/' && !hd[1])
	ctx->cwd[0] = 0, ctx->cwdlen = 0;
    else
	strcpy(ctx->cwd, hd);

    strcpy(ctx->home, ctx->cwd);
    ctx->homelen = ctx->cwdlen;

    hd = ctx->cwd + ctx->rootlen + 1;
    if (*hd && chdir(hd)) {
	logerr("chdir: %s (%s)", hd, ctx->user);
	reply(ctx, MSG_550_No_access_to_homedir);
	ctx->state = ST_conn;
	av_free(avc);
	DebugOut(DEBUG_PROC);
	return;
    }

    if (!ctx->anonymous)
	ctx->real = 1;
    else
	strset(&ctx->email, av_get(avc, AV_A_EMAIL));

    ctx->state = ST_pass;
    ctx->filename[0] = 0;
    ctx->bytecount = 0;
    ctx->filesize = 0;
    ctx->io_offset = 0;
    acl_calc(ctx);

    if (ctx->welcome_bye) {
	file2control(ctx, "421", ctx->welcome);
	io_clr_cb_i(ctx->io, ctx->cfn);
	io_clr_i(ctx->io, ctx->cfn);
	reply(ctx, MSG_421_Service_not_available);
    } else {
	file2control(ctx, "230", ctx->welcome);
	file2control(ctx, "230", ctx->readme);
	if (ctx->anonymous)
	    reply(ctx, MSG_230_Anonymous_logged_in);
	else
	    reply(ctx, MSG_230_User_logged_in);
    }

    av_free(avc);

    DebugOut(DEBUG_PROC);
}
