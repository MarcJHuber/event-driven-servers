/*
 * libmavis_anonftp.c
 * (C)1999-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#define __MAVIS_anonftp__
#define MAVIS_name "anonftp"

#include <stdio.h>
#include <pwd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <dlfcn.h>

#include "misc/sysconf.h"
#include "misc/memops.h"
#include "debug.h"
#include "log.h"
#include "misc/strops.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

#define MAVIS_CTX_PRIVATE	\
	uid_t uid;		\
	gid_t gid;		\
	char *home;		\
	char *incoming;		\
	char *root;

#include "mavis.h"

#define HAVE_mavis_drop_in
static void mavis_drop_in(mavis_ctx * mcx)
{
    Xfree(&mcx->home);
    Xfree(&mcx->root);
    Xfree(&mcx->incoming);
}

/*
mavis module = anonftp - id {
    module = <modulename >
	user - id =...group - id =...home =...root =...incoming =... *
}
*/

#define HAVE_mavis_parse_in
static int mavis_parse_in(mavis_ctx * mcx, struct sym *sym)
{
    while (1) {
	switch (sym->code) {
	case S_script:
	    mavis_script_parse(mcx, sym);
	    continue;
	case S_userid:
	    parse_userid(sym, &mcx->uid, &mcx->gid);
	    continue;
	case S_groupid:
	    parse_groupid(sym, &mcx->gid);
	    continue;
	case S_home:
	    sym_get(sym);
	    parse(sym, S_equal);
	    strset(&mcx->home, sym->buf);
	    sym_get(sym);
	    continue;
	case S_root:
	    sym_get(sym);
	    parse(sym, S_equal);
	    strset(&mcx->root, sym->buf);
	    sym_get(sym);
	    continue;
	case S_upload:
	    sym_get(sym);
	    parse(sym, S_equal);
	    strset(&mcx->incoming, sym->buf);
	    sym_get(sym);
	    continue;
	case S_eof:
	case S_closebra:
	    {
		int bye = 0;
		if (!mcx->uid || !mcx->gid || !mcx->root) {
		    struct passwd *pw;

		    pw = getpwnam("ftp");
		    if (pw) {
			if (!mcx->uid)
			    mcx->uid = pw->pw_uid;
			if (!mcx->gid)
			    mcx->gid = pw->pw_gid;
			if (!mcx->root)
			    mcx->root = Xstrdup(pw->pw_dir);
		    }
		}

		if (!mcx->uid) {
		    logmsg("%s: Fatal: anonymous ftp uid not set!", MAVIS_name);
		    bye++;
		}
		if (!mcx->gid) {
		    logmsg("%s: Fatal: anonymous ftp gid not set!", MAVIS_name);
		    bye++;
		}
		if (!mcx->root) {
		    logmsg("%s: Fatal: anonymous ftp root not set!", MAVIS_name);
		    bye++;
		}
		if (bye)
		    return -1;

		if (!mcx->home)
		    mcx->home = Xstrdup("/");

		return MAVIS_CONF_OK;
	    }
	default:
	    parse_error_expect(sym, S_script, S_userid, S_groupid, S_path, S_mode, S_closebra, S_unknown);
	}
    }
}



#define HAVE_mavis_send_in
static int mavis_send_in(mavis_ctx * mcx, av_ctx ** ac)
{
    char *t, *u;
    DebugIn(DEBUG_MAVIS);
    t = av_get(*ac, AV_A_TYPE);
    u = av_get(*ac, AV_A_USER);
    if (strcmp(t, AV_V_TYPE_FTP)
	|| (strcasecmp(u, "ftp")
	    && strcasecmp(u, "anonymous"))) {
	Debug((DEBUG_MAVIS, "- %s = MAVIS_DOWN (no anon ftp)\n", __func__));
	return MAVIS_DOWN;
    }

    av_set(*ac, AV_A_RESULT, AV_V_RESULT_OK);
    av_setf(*ac, AV_A_UID, "%d", (int) mcx->uid);
    av_setf(*ac, AV_A_GID, "%d", (int) mcx->gid);
    av_set(*ac, AV_A_HOME, mcx->home);
    av_set(*ac, AV_A_ROOT, mcx->root);
    av_set(*ac, AV_A_FTP_ANONYMOUS, AV_V_BOOL_TRUE);
    if (mcx->incoming)
	av_set(*ac, AV_A_ANON_INCOMING, mcx->incoming);
    if ((t = av_get(*ac, AV_A_PASSWORD)))
	av_set(*ac, AV_A_EMAIL, t);
    Debug((DEBUG_MAVIS, "- %s = MAVIS_FINAL\n", __func__));
    return MAVIS_FINAL;
}

#include "mavis_glue.c"
