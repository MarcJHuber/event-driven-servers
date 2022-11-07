/*
 * libmavis_tacinfo_cache.c
 * Caches MAVIS-TACACS+ authentication results to disk for later authorizations.
 * (C)2002-2021 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 * 
 * $Id$
 *
 */

#define MAVIS_name "tacinfo_cache"

#include "misc/sysconf.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <dlfcn.h>
#include <sys/time.h>
#include <unistd.h>

#include "misc/io.h"
#include "debug.h"
#include "log.h"
#include "misc/strops.h"
#include "misc/tohex.h"
#include "misc/mymd5.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

#define MAVIS_CTX_PRIVATE		\
		char *hashdir;		\
		char *hashfile;		\
		char *hashfile_tmp;	\
		off_t hashfile_offset;	\
		int cached;		\
		uid_t uid;		\
		gid_t gid;		\
		uid_t euid;		\
		gid_t egid;

#include "mavis.h"

#define HAVE_mavis_init_in
static int mavis_init_in(mavis_ctx * mcx)
{
    DebugIn(DEBUG_MAVIS);

    mcx->cached = 0;
    mcx->euid = geteuid();
    mcx->egid = getegid();

    if (!mcx->hashdir)
	logmsg("Warning: %s module lacks directory definition", MAVIS_name);
    else {
	int fn;
	pid_t pid;
	struct stat st;
	size_t dirlen = strlen(mcx->hashdir);
	while (dirlen - 1 > 0 && mcx->hashdir[dirlen - 1] == '/')
	    dirlen--;
	mcx->hashdir[dirlen] = 0;

	UNUSED_RESULT(setegid(mcx->gid));
	UNUSED_RESULT(seteuid(mcx->uid));

	if (stat(mcx->hashdir, &st))
	    mkdir(mcx->hashdir, 0700);

	UNUSED_RESULT(seteuid(mcx->euid));
	UNUSED_RESULT(setegid(mcx->egid));

	if (stat(mcx->hashdir, &st) && (!mkdir(mcx->hashdir, 0700) && errno != EEXIST))
	    UNUSED_RESULT(chown(mcx->hashdir, mcx->uid, mcx->gid));

	if (stat(mcx->hashdir, &st) || !S_ISDIR(st.st_mode))
	    logerr("module %s: directory %s doesn not exist", MAVIS_name, mcx->hashdir);

	mcx->hashfile_tmp = calloc(1, dirlen + 39 + 1 + 2 * sizeof(pid) + 10 /* safety margin in case I've messed up counting characters */ );
	strncpy(mcx->hashfile_tmp, mcx->hashdir, dirlen);
	mcx->hashfile_tmp[dirlen++] = '/';
	pid = getpid();
	mcx->hashfile_tmp[dirlen + 35] = '-';
	tohex((u_char *) & pid, sizeof(pid), mcx->hashfile_tmp + dirlen + 36);
	memcpy(mcx->hashfile_tmp + dirlen, mcx->hashfile_tmp + dirlen + 36, 8);
	UNUSED_RESULT(setegid(mcx->gid));
	UNUSED_RESULT(seteuid(mcx->uid));
	fn = open(mcx->hashfile_tmp, O_CREAT | O_WRONLY, 0600);
	if (fn > -1) {
	    close(fn);
	    unlink(mcx->hashfile_tmp);
	} else {
	    logerr("module %s: can't write to directory %s", MAVIS_name, mcx->hashdir);
	    free(mcx->hashdir);
	    mcx->hashdir = NULL;
	    free(mcx->hashfile_tmp);
	    mcx->hashfile_tmp = NULL;

	}
	UNUSED_RESULT(setegid(mcx->gid));
	UNUSED_RESULT(seteuid(mcx->uid));
	mcx->hashfile_tmp[dirlen + 2] = '/';
	mcx->hashfile = calloc(1, dirlen + 39 + 10 /* safety margin, see above */ );
	memcpy(mcx->hashfile, mcx->hashfile_tmp, 36);
	mcx->hashfile_offset = dirlen;
    }

    DebugOut(DEBUG_MAVIS);
    return MAVIS_INIT_OK;
}

/*
id = tac_plus {
    mavis path = ../../mavis/obj.%O
    mavis module = tac_info_cache {
        userid = 100
        groupid = 100
        directory = /where/ever
    }
    mavis module = auth {
*/

#define HAVE_mavis_parse_in
static int mavis_parse_in(mavis_ctx * mcx, struct sym *sym)
{
    DebugIn(DEBUG_MAVIS);
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
	case S_directory:
	    sym_get(sym);
	    parse(sym, S_equal);
	    strset(&mcx->hashdir, sym->buf);
	    sym_get(sym);
	    continue;
	case S_eof:
	case S_closebra:
	    DebugOut(DEBUG_MAVIS);
	    return MAVIS_CONF_OK;
	default:
	    parse_error_expect(sym, S_script, S_userid, S_groupid, S_directory, S_closebra, S_unknown);
	}
    }
    DebugOut(DEBUG_MAVIS);
}

#define HAVE_mavis_drop_in
static void mavis_drop_in(mavis_ctx * mcx)
{
    Xfree(&mcx->hashdir);
    Xfree(&mcx->hashfile);
    Xfree(&mcx->hashfile_tmp);
}

static void get_hash(av_ctx * ac, char *buf)
{
    u_char u[16];
    char *t;
    myMD5_CTX m;
    DebugIn(DEBUG_MAVIS);
    myMD5Init(&m);
    if ((t = av_get(ac, AV_A_USER)))
	myMD5Update(&m, (u_char *) t, strlen(t));
    if ((t = av_get(ac, AV_A_SERVERIP)))
	myMD5Update(&m, (u_char *) t, strlen(t));
    if ((t = av_get(ac, AV_A_IPADDR)))
	myMD5Update(&m, (u_char *) t, strlen(t));
    if ((t = av_get(ac, AV_A_REALM)))
	myMD5Update(&m, (u_char *) t, strlen(t));

    myMD5Final(u, &m);
    tohex(u, 16, buf);
    DebugOut(DEBUG_MAVIS);
}

#define HAVE_mavis_send_in
static int mavis_send_in(mavis_ctx * mcx, av_ctx ** ac)
{
    int fn;
    char *t;

    DebugIn(DEBUG_MAVIS);
    if (!mcx->hashfile)
	return MAVIS_DOWN;
    t = av_get(*ac, AV_A_TYPE);
    if (!t || strcmp(t, AV_V_TYPE_TACPLUS))
	return MAVIS_DOWN;
    t = av_get(*ac, AV_A_TACTYPE);
    if (!t || strcmp(t, AV_V_TACTYPE_INFO))
	return MAVIS_DOWN;

    get_hash(*ac, mcx->hashfile + mcx->hashfile_offset + 3);
    mcx->hashfile[mcx->hashfile_offset] = mcx->hashfile[mcx->hashfile_offset + 3];
    mcx->hashfile[mcx->hashfile_offset + 1] = mcx->hashfile[mcx->hashfile_offset + 4];
    UNUSED_RESULT(setegid(mcx->gid));
    UNUSED_RESULT(seteuid(mcx->uid));

    fn = open(mcx->hashfile, O_RDONLY);
    UNUSED_RESULT(seteuid(mcx->euid));
    UNUSED_RESULT(setegid(mcx->egid));
    if (fn > -1) {
	char *c;
	av_ctx *a = av_new(NULL, NULL);
	struct stat st;
	fstat(fn, &st);
	c = alloca(st.st_size + 1);
	c[st.st_size] = 0;
	if (read(fn, c, st.st_size)) {
	}
	close(fn);
	av_char_to_array(a, c, NULL);
	av_set(*ac, AV_A_TACPROFILE, av_get(a, AV_A_TACPROFILE));
	av_set(*ac, AV_A_TACCLIENT, av_get(a, AV_A_TACCLIENT));
	av_set(*ac, AV_A_TACMEMBER, av_get(a, AV_A_TACMEMBER));
	av_set(*ac, AV_A_UID, av_get(a, AV_A_UID));
	av_set(*ac, AV_A_GID, av_get(a, AV_A_GID));
	av_set(*ac, AV_A_GIDS, av_get(a, AV_A_GIDS));
	av_set(*ac, AV_A_HOME, av_get(a, AV_A_HOME));
	av_set(*ac, AV_A_ROOT, av_get(a, AV_A_ROOT));
	av_set(*ac, AV_A_SHELL, av_get(a, AV_A_SHELL));
	av_set(*ac, AV_A_PATH, av_get(a, AV_A_PATH));
	av_set(*ac, AV_A_DN, av_get(a, AV_A_DN));
	av_set(*ac, AV_A_MEMBEROF, av_get(a, AV_A_MEMBEROF));
	av_set(*ac, AV_A_SSHKEYHASH, av_get(a, AV_A_SSHKEYHASH));
	av_free(a);
	av_set(*ac, AV_A_RESULT, AV_V_RESULT_OK);
	mcx->cached = 1;
	DebugOut(DEBUG_MAVIS);
	return MAVIS_FINAL;
    }

    DebugOut(DEBUG_MAVIS);
    return MAVIS_DOWN;
}

static int write_av(av_ctx * ac, int fn, int attr)
{
    int res = 0;
    char *t = av_get(ac, attr);
    if (t) {
	char buf[40];
	size_t len;
	len = snprintf(buf, sizeof(buf), "%d ", attr);
	res |= ((ssize_t) len != write(fn, buf, len));
	len = strlen(t);
	res |= ((ssize_t) len != write(fn, t, len));
	res |= (1 != write(fn, "\n", 1));
    }
    return res;
}

#define HAVE_mavis_recv_out
static int mavis_recv_out(mavis_ctx * mcx, av_ctx ** ac)
{
    int fn, res = 0;
    char *t;

    if (mcx->cached) {
	mcx->cached = 0;
	return MAVIS_DOWN;
    }

    if (!mcx->hashdir)
	return MAVIS_DOWN;

    DebugIn(DEBUG_MAVIS);

    t = av_get(*ac, AV_A_RESULT);
    if (!t || strcmp(t, AV_V_RESULT_OK))
	return MAVIS_DOWN;
    t = av_get(*ac, AV_A_TYPE);
    if (!t || strcmp(t, AV_V_TYPE_TACPLUS))
	return MAVIS_DOWN;
    t = av_get(*ac, AV_A_TACTYPE);
    if (!t || (strcmp(t, AV_V_TACTYPE_AUTH) && strcmp(t, AV_V_TACTYPE_INFO)))
	return MAVIS_DOWN;

    get_hash(*ac, mcx->hashfile + mcx->hashfile_offset + 3);
    mcx->hashfile[mcx->hashfile_offset] = mcx->hashfile[mcx->hashfile_offset + 3];
    mcx->hashfile[mcx->hashfile_offset + 1] = mcx->hashfile[mcx->hashfile_offset + 4];
    mcx->hashfile_tmp[mcx->hashfile_offset] = mcx->hashfile[mcx->hashfile_offset + 3];
    mcx->hashfile_tmp[mcx->hashfile_offset + 1] = mcx->hashfile[mcx->hashfile_offset + 4];
    memcpy(mcx->hashfile_tmp + mcx->hashfile_offset + 3, mcx->hashfile + mcx->hashfile_offset + 3, 32);
    mcx->hashfile_tmp[mcx->hashfile_offset + 3] = 0;

    UNUSED_RESULT(setegid(mcx->gid));
    UNUSED_RESULT(seteuid(mcx->uid));

    mkdir(mcx->hashfile_tmp, 0700);
    mcx->hashfile_tmp[mcx->hashfile_offset + 3] = '/';

    fn = open(mcx->hashfile_tmp, O_CREAT | O_WRONLY, 0600);
    if (fn > -1) {
	res |= write_av(*ac, fn, AV_A_TACPROFILE);
	res |= write_av(*ac, fn, AV_A_TACCLIENT);
	res |= write_av(*ac, fn, AV_A_TACMEMBER);
	res |= write_av(*ac, fn, AV_A_UID);
	res |= write_av(*ac, fn, AV_A_GID);
	res |= write_av(*ac, fn, AV_A_GIDS);
	res |= write_av(*ac, fn, AV_A_HOME);
	res |= write_av(*ac, fn, AV_A_ROOT);
	res |= write_av(*ac, fn, AV_A_SHELL);
	res |= write_av(*ac, fn, AV_A_PATH);
	res |= write_av(*ac, fn, AV_A_DN);
	res |= write_av(*ac, fn, AV_A_MEMBEROF);
	res |= write_av(*ac, fn, AV_A_SSHKEYHASH);
	res |= (-1 == close(fn));
	if (res)
	    unlink(mcx->hashfile_tmp);
	else
	    rename(mcx->hashfile_tmp, mcx->hashfile);
    }

    UNUSED_RESULT(seteuid(mcx->euid));
    UNUSED_RESULT(setegid(mcx->egid));

    DebugOut(DEBUG_MAVIS);
    return MAVIS_DOWN;
}

#include "mavis_glue.c"
