/*
 * libmavis_tacauth_limit.c
 * Caches MAVIS-TACACS+ authentication results to disk for later authorizations.
 * (C)2002-2024 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 * 
 * $Id$
 *
 */

#define MAVIS_name "tacauth_limit"

#include "misc/sysconf.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <dlfcn.h>
#include <sys/time.h>
#include <sys/uio.h>
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
		int skip_recv_out;	\
		uid_t uid;		\
		gid_t gid;		\
		uid_t euid;		\
		gid_t egid;		\
		uint64_t hashbits;	\
		u_int blacklist_count;	\
		time_t blacklist_period;

#include "mavis.h"

#define HAVE_mavis_init_in
static int mavis_init_in(mavis_ctx * mcx)
{
    DebugIn(DEBUG_MAVIS);

    mcx->skip_recv_out = 0;
    mcx->euid = geteuid();
    mcx->egid = getegid();

    if (!mcx->hashdir)
	logmsg("Warning: %s module lacks directory definition", MAVIS_name);
    else {
	int fn;
	pid_t pid;
	struct stat st;
	size_t dirlen = strlen(mcx->hashdir);
	while (dirlen > 1 && mcx->hashdir[dirlen - 1] == '/')
	    dirlen--;
	mcx->hashdir[dirlen] = 0;

	UNUSED_RESULT(setegid(mcx->gid));
	UNUSED_RESULT(seteuid(mcx->uid));

	if (stat(mcx->hashdir, &st))
	    mkdir(mcx->hashdir, 0700);

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
	    DebugOut(DEBUG_MAVIS);
	    return MAVIS_INIT_ERR;
	}

	UNUSED_RESULT(setegid(mcx->egid));
	UNUSED_RESULT(seteuid(mcx->euid));
	mcx->hashfile_tmp[dirlen + 2] = '/';
	mcx->hashfile = calloc(1, dirlen + 39 + 10 /* safety margin, see above */ );
	memcpy(mcx->hashfile, mcx->hashfile_tmp, 36);
	mcx->hashfile_offset = dirlen;
    }

    DebugOut(DEBUG_MAVIS);
    return MAVIS_INIT_OK;
}

#define HAVE_mavis_parse_in
static int mavis_parse_in(mavis_ctx * mcx, struct sym *sym)
{
    DebugIn(DEBUG_MAVIS);
    mcx->blacklist_period = (time_t) 15 *60;
    mcx->blacklist_count = (u_int) 5;
    mcx->hashbits = (1 << AV_A_USER) | (1 << AV_A_IPADDR) | (1 << AV_A_REALM);

    while (1) {
	switch (sym->code) {
	case S_script:
	    mavis_script_parse(mcx, NULL, sym);
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
	case S_blacklist:
	    sym_get(sym);
	    switch (sym->code) {
	    case S_time:
		sym_get(sym);
		parse(sym, S_equal);
		mcx->blacklist_period = (time_t) parse_int(sym);;
		break;
	    case S_count:
		sym_get(sym);
		parse(sym, S_equal);
		mcx->blacklist_count = (u_int) parse_int(sym);;
		break;
	    default:
		parse_error_expect(sym, S_time, S_count, S_unknown);
	    }
	    continue;
	case S_hash:
	    sym_get(sym);
	    parse(sym, S_equal);
	    mcx->hashbits = 0;
	    do {
		int i = av_attr_token_to_i(sym);
		if (i < 0)
		    parse_error(sym, "%s is not a recognized MAVIS attribute", sym->buf);
		sym_get(sym);
		mcx->hashbits |= (1 << i);
	    } while (parse_comma(sym));
	    continue;
	case S_eof:
	case S_closebra:
	    DebugOut(DEBUG_MAVIS);
	    return MAVIS_CONF_OK;
	case S_action:
	    mavis_module_parse_action(mcx, sym);
	    continue;
	default:
	    parse_error_expect(sym, S_script, S_userid, S_groupid, S_directory, S_hash, S_action, S_closebra, S_unknown);
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

static void get_hash(mavis_ctx * mcx, av_ctx * ac, char *buf)
{
    u_char u[16];
    myMD5_CTX m;
    DebugIn(DEBUG_MAVIS);
    myMD5Init(&m);
    uint64_t hashbits = mcx->hashbits;
    for (int i = 0; i < AV_A_ARRAYSIZE; i++) {
	char *t;
	if ((hashbits & 1) && (t = av_get(ac, i))) {
	    myMD5Update(&m, (u_char *) t, strlen(t));
	    myMD5Update(&m, (u_char *) " ", 1);
	}
	hashbits >>= 1;
    }
    myMD5Final(u, &m);
    tohex(u, 16, buf);
    DebugOut(DEBUG_MAVIS);
}

#define HAVE_mavis_send_in
static int mavis_send_in(mavis_ctx * mcx, av_ctx ** ac)
{
    int fn;

    DebugIn(DEBUG_MAVIS);
    if (!mcx->hashfile)
	return MAVIS_DOWN;
    char *t = av_get(*ac, AV_A_TYPE);
    if (!t || strcmp(t, AV_V_TYPE_TACPLUS))
	return MAVIS_DOWN;
    t = av_get(*ac, AV_A_TACTYPE);
    if (!t || strcmp(t, AV_V_TACTYPE_AUTH))
	return MAVIS_DOWN;

    get_hash(mcx, *ac, mcx->hashfile + mcx->hashfile_offset + 3);
    mcx->hashfile[mcx->hashfile_offset] = mcx->hashfile[mcx->hashfile_offset + 3];
    mcx->hashfile[mcx->hashfile_offset + 1] = mcx->hashfile[mcx->hashfile_offset + 4];
    UNUSED_RESULT(setegid(mcx->gid));
    UNUSED_RESULT(seteuid(mcx->uid));
    fn = open(mcx->hashfile, O_RDONLY);
    int res = MAVIS_DOWN;
    if (fn > -1) {
	struct stat st = { 0 };
	if (!fstat(fn, &st) && (st.st_mtime + mcx->blacklist_period < io_now.tv_sec)) {
	    unlink(mcx->hashfile);	// blacklist period expired
	} else {
	    uint32_t i = 0;
	    char buf[80];
	    ssize_t len = read(fn, buf, sizeof(buf));
	    if (len > 0) {
		buf[len] = 0;
		sscanf(buf, "count = %u", &i);
	    }
	    if (i >= mcx->blacklist_count) {
		av_setf(*ac, AV_A_USER_RESPONSE, "Authentication failure (banned for another %ld seconds) [id: %s]",
			(long) (st.st_mtime + mcx->blacklist_period - io_now.tv_sec), mcx->hashfile + mcx->hashfile_offset + 3);
		av_set(*ac, AV_A_RESULT, AV_V_RESULT_FAIL);
		mcx->skip_recv_out = 1;
		res = MAVIS_FINAL;
	    }
	}
	close(fn);
    }
    UNUSED_RESULT(seteuid(mcx->euid));
    UNUSED_RESULT(setegid(mcx->egid));

    DebugOut(DEBUG_MAVIS);
    return res;
}

#define HAVE_mavis_recv_out
static int mavis_recv_out(mavis_ctx * mcx, av_ctx ** ac)
{
    if (mcx->skip_recv_out) {
	mcx->skip_recv_out = 0;
	return MAVIS_DOWN;
    }

    if (!mcx->hashdir)
	return MAVIS_DOWN;

    DebugIn(DEBUG_MAVIS);

    char *t = av_get(*ac, AV_A_TYPE);
    if (!t || strcmp(t, AV_V_TYPE_TACPLUS))
	return MAVIS_DOWN;
    t = av_get(*ac, AV_A_TACTYPE);
    if (!t || strcmp(t, AV_V_TACTYPE_AUTH))
	return MAVIS_DOWN;

    get_hash(mcx, *ac, mcx->hashfile + mcx->hashfile_offset + 3);
    mcx->hashfile[mcx->hashfile_offset] = mcx->hashfile[mcx->hashfile_offset + 3];
    mcx->hashfile[mcx->hashfile_offset + 1] = mcx->hashfile[mcx->hashfile_offset + 4];

    t = av_get(*ac, AV_A_RESULT);
    if (!t)
	return MAVIS_DOWN;

    if (!strcmp(t, AV_V_RESULT_OK)) {
	unlink(mcx->hashfile);
	return MAVIS_DOWN;
    }

    if (strcmp(t, AV_V_RESULT_FAIL))
	return MAVIS_DOWN;

    mcx->hashfile_tmp[mcx->hashfile_offset] = mcx->hashfile[mcx->hashfile_offset + 3];
    mcx->hashfile_tmp[mcx->hashfile_offset + 1] = mcx->hashfile[mcx->hashfile_offset + 4];
    memcpy(mcx->hashfile_tmp + mcx->hashfile_offset + 3, mcx->hashfile + mcx->hashfile_offset + 3, 32);
    mcx->hashfile_tmp[mcx->hashfile_offset + 3] = 0;

    UNUSED_RESULT(setegid(mcx->gid));
    UNUSED_RESULT(seteuid(mcx->uid));

    mkdir(mcx->hashfile_tmp, 0700);
    mcx->hashfile_tmp[mcx->hashfile_offset + 3] = '/';

    int fn = open(mcx->hashfile, O_RDONLY);
    uint32_t i = 0;
    if (fn > -1) {
	char buf[80];
	ssize_t len = read(fn, buf, sizeof(buf));
	if (len > 0) {
	    buf[len] = 0;
	    sscanf(buf, "count = %u", &i);
	}
	close(fn);
    }
    fn = open(mcx->hashfile_tmp, O_CREAT | O_WRONLY, 0600);
    if (fn > -1) {
	i++;
	char buf[80];
	int len = snprintf(buf, sizeof(buf), "count = %u\n", i);
	write(fn, buf, len);
	uint64_t hashbits = mcx->hashbits;
	for (int j = 0; j < AV_A_ARRAYSIZE; j++) {
	    char *t;
	    if ((hashbits & 1) && (t = av_get(*ac, j))) {
		struct iovec iov[4] = {
		    {.iov_base = av_char[j].name,.iov_len = strlen(av_char[j].name) },
		    {.iov_base = " = ",.iov_len = 3 },
		    {.iov_base = t,.iov_len = strlen(t) },
		    {.iov_base = "\n",.iov_len = 1 }
		};
		writev(fn, iov, 4);
	    }
	    hashbits >>= 1;
	}
	close(fn);
	rename(mcx->hashfile_tmp, mcx->hashfile);
    }

    UNUSED_RESULT(seteuid(mcx->euid));
    UNUSED_RESULT(setegid(mcx->egid));

    DebugOut(DEBUG_MAVIS);
    return MAVIS_DOWN;
}

#include "mavis_glue.c"
