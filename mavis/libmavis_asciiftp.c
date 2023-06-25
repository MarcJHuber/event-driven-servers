/*
 * libmavis_asciiftp.c
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#define MAVIS_name "asciiftp"

#include "misc/sysconf.h"
#include "misc/strops.h"
#include "misc/memops.h"
#include "misc/io.h"
#include "debug.h"
#include <unistd.h>
#include <fcntl.h>
#include <grp.h>
#include <dlfcn.h>

static const char rcsid[] __attribute__((used)) = "$Id$";

#define MAVIS_CTX_PRIVATE	\
	char *asciiftp_file;	\
	long asciiftp_uid_min;	\
	long asciiftp_uid_max;	\
	long asciiftp_gid_min;	\
	long asciiftp_gid_max;	\

#include "mavis.h"

static char *find_user(mavis_ctx *, av_ctx *, char *, size_t, char *);

/*
file =...user - id(min | max) =...group - id(min | max) =...
*/
#define HAVE_mavis_parse_in
static int mavis_parse_in(mavis_ctx * mcx, struct sym *sym)
{
    uid_t uid;
    gid_t gid;

    while (1) {
	switch (sym->code) {
	case S_script:
	    mavis_script_parse(mcx, sym);
	    continue;
	case S_userid:
	    sym_get(sym);
	    switch (sym->code) {
	    case S_min:
		parse_userid(sym, &uid, NULL);
		mcx->asciiftp_uid_min = (long) uid;
		continue;
	    case S_max:
		parse_userid(sym, &uid, NULL);
		mcx->asciiftp_uid_max = (long) uid;
		continue;
	    default:
		parse_error_expect(sym, S_min, S_max, S_unknown);
	    }
	case S_groupid:
	    sym_get(sym);
	    switch (sym->code) {
	    case S_min:
		parse_groupid(sym, &gid);
		mcx->asciiftp_gid_min = (long) gid;
		continue;
	    case S_max:
		parse_groupid(sym, &gid);
		mcx->asciiftp_gid_max = (long) gid;
		continue;
	    default:
		parse_error_expect(sym, S_min, S_max, S_unknown);
	    }
	case S_file:
	    sym_get(sym);
	    parse(sym, S_equal);
	    strset(&mcx->asciiftp_file, sym->buf);
	    sym_get(sym);
	    continue;
	case S_eof:
	case S_closebra:
	    return MAVIS_CONF_OK;
	case S_action:
	    mavis_module_parse_action(mcx, sym);
	    continue;
	default:
	    parse_error_expect(sym, S_script, S_userid, S_groupid, S_file, S_closebra, S_action, S_unknown);
	}
    }
}




#define HAVE_mavis_drop_in
static void mavis_drop_in(mavis_ctx * mcx)
{
    Xfree(&mcx->asciiftp_file);
}

#define HAVE_mavis_send_in
static int mavis_send_in(mavis_ctx * mcx, av_ctx ** ac)
{
    int n = 0;
    char *t, *u, *m;
    uid_t uid;
    long user_id, group_id;
    char *line;
    char buf[8192];
#define MAXFIELDS 20
    char *field[MAXFIELDS];

    if (!mcx->asciiftp_file) {
	av_set(*ac, AV_A_RESULT, AV_V_RESULT_ERROR);
	av_set(*ac, AV_A_COMMENT, "asciiftp_file not specified");
    }

    t = av_get(*ac, AV_A_TYPE);

    if (strcmp(t, AV_V_TYPE_FTP))
	return MAVIS_DOWN;

    u = av_get(*ac, AV_A_USER);

/* No VHOST support yet. Let downstream modules decide what to do for
 * anonymous FTP
 */

    m = av_get(*ac, AV_A_FTP_ANONYMOUS);
    if (m && !strcmp(m, AV_V_BOOL_TRUE))
	return MAVIS_DOWN;

    uid = geteuid();
    UNUSED_RESULT(seteuid(0));
    line = find_user(mcx, *ac, buf, sizeof(buf), u);
    UNUSED_RESULT(seteuid(uid));

    if (!line)
	return MAVIS_DOWN;

    field[7] = 0;

    while (line && n < 8) {
	field[n++] = line;
	line = strchr(line, ':');
	if (line)
	    *line++ = 0;
    }

    av_set(*ac, AV_A_IDENTITY_SOURCE, mcx->identity_source_name);
    /* FIXME -- untested code */

    if (n < 7 || !field[0] || !field[2] || !field[3] || !field[4] || !field[5] || !field[6]) {
	av_set(*ac, AV_A_COMMENT, "line format error");
	av_set(*ac, AV_A_RESULT, AV_V_RESULT_ERROR);
	return MAVIS_FINAL;
    }

    if (!strcasecmp(field[5], "anon")) {
	av_set(*ac, AV_A_FTP_ANONYMOUS, AV_V_BOOL_TRUE);
	av_set(*ac, AV_A_RESULT, AV_V_RESULT_OK);
    } else {
	av_set(*ac, AV_A_DBPASSWORD, field[1]);
	if (field[7])
	    av_set(*ac, AV_A_CERTSUBJ, field[7]);
    }

    user_id = strtol(field[2], NULL, 10);
    group_id = strtol(field[3], NULL, 10);

    if ((mcx->asciiftp_uid_min > -1 && user_id < mcx->asciiftp_uid_min) ||
	(mcx->asciiftp_uid_max > -1 && user_id > mcx->asciiftp_uid_max) ||
	(mcx->asciiftp_gid_min > -1 && group_id < mcx->asciiftp_gid_min) || (mcx->asciiftp_gid_max > -1 && group_id > mcx->asciiftp_gid_max)) {
	av_set(*ac, AV_A_COMMENT, "uid/gid out of range");
	av_set(*ac, AV_A_RESULT, AV_V_RESULT_FAIL);
	return MAVIS_FINAL;
    }

    av_set(*ac, AV_A_UID, field[2]);
    av_set(*ac, AV_A_GIDS, field[3]);

    t = strchr(field[3], ',');
    if (t)
	*t = 0;
    av_set(*ac, AV_A_GID, field[3]);

    av_set(*ac, AV_A_ROOT, field[5]);
    av_set(*ac, AV_A_HOME, field[6]);

    return MAVIS_FINAL;
}

static char *find_user(mavis_ctx * mcx, av_ctx * ac, char *inbuf, size_t inbuflen, char *user)
{
    size_t offset = 0;
    ssize_t inlength;
    char *linestart = inbuf;
    char *lineend;
    size_t userlen = strlen(user);
    int fn;

    fn = open(mcx->asciiftp_file, O_RDONLY);
    if (fn < 0) {
	av_setf(ac, AV_A_COMMENT, "opening %s failed", mcx->asciiftp_file);
	av_set(ac, AV_A_RESULT, AV_V_RESULT_ERROR);
	return NULL;
    }

    user[userlen] = ':';

    while ((inlength = Read(fn, inbuf + offset, inbuflen - 1 - offset)) > 0) {
	inlength += offset;
	inbuf[inlength] = 0;
	linestart = inbuf;

	while ((lineend = strchr(linestart, '\n'))) {
	    *lineend = 0;

	    if (linestart[0] != '#' && !strncmp(user, linestart, userlen + 1)) {
		user[userlen] = 0;
		close(fn);
		return linestart;
	    }
	    linestart = lineend + 1;
	}

	offset = inbuf + inlength - linestart;
	if (offset)
	    memmove(inbuf, linestart, offset);
    }

    user[userlen] = 0;
    close(fn);

    return NULL;
}

#define HAVE_mavis_new
static void mavis_new(mavis_ctx * mcx)
{
    mcx->asciiftp_uid_min = -1;
    mcx->asciiftp_uid_max = -1;
    mcx->asciiftp_gid_min = -1;
    mcx->asciiftp_gid_max = -1;
}

#include "mavis_glue.c"
