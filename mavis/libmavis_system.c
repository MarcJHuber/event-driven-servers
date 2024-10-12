/*
 * libmavis_system.c
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#define MAVIS_name "system"

#include "misc/sysconf.h"
#include <pwd.h>
#ifdef WITH_SHADOWPWD
#include <shadow.h>
#endif				/* WITH_SHADOWPWD */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <grp.h>
#include <errno.h>
#include <unistd.h>
#include <dlfcn.h>
#include "misc/strops.h"
#include "misc/io.h"
#include "groups.h"
#include "misc/memops.h"
#include "debug.h"
#include "log.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

#define MAVIS_CTX_PRIVATE		\
	int initialized;		\
	int ftp_chroot;			\
	char *passwordfile;		\
	int honour_ftpusers;		\
	char *ftpuserspath;		\
	int lookup_sslusers;		\
	char *ssluserspath;		\
	int require_valid_shell;	\
	char *shellpath;		\
    	struct passwd pw;		\
	char inbuf[16384];	\
	void *libcrypt;			\
	char *(*crypt) (const char *, const char *);

#include "mavis.h"

static int valid_user(mavis_ctx *, char *);
static int valid_shell(mavis_ctx *, char *);
static void lookup_ssluser(mavis_ctx *, av_ctx *, char *);

#define HAVE_mavis_init_in
static int mavis_init_in(mavis_ctx * mcx)
{
    DebugIn(DEBUG_MAVIS);
    if (!mcx->initialized) {
	mcx->initialized++;
	if (mcx->require_valid_shell && !mcx->shellpath)
	    mcx->shellpath = Xstrdup("/etc/shells");
	if (mcx->honour_ftpusers && !mcx->ftpuserspath)
	    mcx->ftpuserspath = Xstrdup("/etc/ftpusers");
	if (mcx->lookup_sslusers && !mcx->ssluserspath)
	    mcx->ssluserspath = Xstrdup("/etc/ssl.users");
	if (geteuid())
	    logmsg("Warning: SYSTEM module requires root privileges");
#ifdef WITH_LIB_CRYPT
	/* We need to make sure to get crypt(3) from libcrypt.so, not from
	 * the OpenSSL libcrypto.so library, which may be already loaded.
	 * Reason for that is that the libcrypt version may support additional
	 * encryption algorithms, e.g. MD5.
	 */
	mcx->libcrypt = dlopen("libcrypt.so", RTLD_LAZY);
	if (mcx->libcrypt) {
	    mcx->crypt = (char *(*)(const char *, const char *))
		dlsym(mcx->libcrypt, DLSYM_PREFIX "crypt");
	    if (!mcx->crypt) {
		dlclose(mcx->libcrypt);
		mcx->libcrypt = NULL;
		mcx->crypt = crypt;
	    }
	}
	if (!mcx->crypt)
#endif
	    mcx->crypt = crypt;
    }
    DebugOut(DEBUG_MAVIS);
    return MAVIS_INIT_OK;
}

/*
chroot = yes | no
    passwd file = <file >
    ftpusers file = <file >
    shells file = <file >
    sslusers file = <file >
    check = ftpusers check = shells check = sslusers
*/
#define HAVE_mavis_parse_in
static int mavis_parse_in(mavis_ctx * mcx, struct sym *sym)
{
    while (1) {
	switch (sym->code) {
	case S_script:
	    mavis_script_parse(mcx, NULL, sym);
	    continue;
	case S_chroot:
	    sym_get(sym);
	    parse(sym, S_equal);
	    mcx->ftp_chroot = parse_bool(sym);
	    continue;
	case S_passwd:
	    sym_get(sym);
	    parse(sym, S_file);
	    parse(sym, S_equal);
	    strset(&mcx->passwordfile, sym->buf);
	    sym_get(sym);
	    continue;
	case S_ftpusers:
	    sym_get(sym);
	    parse(sym, S_file);
	    parse(sym, S_equal);
	    strset(&mcx->ftpuserspath, sym->buf);
	    sym_get(sym);
	    continue;
	case S_shells:
	    sym_get(sym);
	    parse(sym, S_file);
	    parse(sym, S_equal);
	    strset(&mcx->shellpath, sym->buf);
	    sym_get(sym);
	    continue;
	case S_sslusers:
	    sym_get(sym);
	    parse(sym, S_file);
	    parse(sym, S_equal);
	    strset(&mcx->ssluserspath, sym->buf);
	    sym_get(sym);
	    continue;
	case S_check:
	    sym_get(sym);
	    switch (sym->code) {
	    case S_ftpusers:
		sym_get(sym);
		parse(sym, S_equal);
		mcx->honour_ftpusers = parse_bool(sym);
		break;
	    case S_shells:
		sym_get(sym);
		parse(sym, S_equal);
		mcx->require_valid_shell = parse_bool(sym);
		break;
	    case S_sslusers:
		sym_get(sym);
		parse(sym, S_equal);
		mcx->lookup_sslusers = parse_bool(sym);
		break;
	    default:
		parse_error_expect(sym, S_ftpusers, S_shells, S_sslusers, S_unknown);
	    }
	    continue;
	case S_eof:
	case S_closebra:
	    return MAVIS_CONF_OK;
	case S_action:
	    mavis_module_parse_action(mcx, sym);
	    continue;
	default:
	    parse_error_expect(sym, S_script, S_userid, S_groupid, S_path, S_mode, S_action, S_closebra, S_unknown);
	}
    }
}

#define HAVE_mavis_drop_in
static void mavis_drop_in(mavis_ctx * mcx)
{
    Xfree(&mcx->passwordfile);
    Xfree(&mcx->ftpuserspath);
    Xfree(&mcx->ssluserspath);
    Xfree(&mcx->shellpath);
#ifdef WITH_LIB_CRYPT
    if (mcx->libcrypt)
	dlclose(mcx->libcrypt);
#endif
}

static struct passwd *parse_pwent(mavis_ctx * mcx, char *s)
{
    char *t = s;
    char *n;

    memset(&mcx->pw, 0, sizeof(mcx->pw));

    mcx->pw.pw_name = t;
    if (!(t = strchr(t, ':')))
	return NULL;
    *t++ = 0;

    mcx->pw.pw_passwd = t;
    if (!(t = strchr(t, ':')))
	return NULL;
    *t++ = 0;

    n = t;
    if (!(t = strchr(t, ':')))
	return NULL;
    *t++ = 0;
    mcx->pw.pw_uid = (uid_t) strtoul(n, NULL, 10);

    n = t;
    if (!(t = strchr(t, ':')))
	return NULL;
    *t++ = 0;
    mcx->pw.pw_gid = (gid_t) strtoul(n, NULL, 10);

    mcx->pw.pw_gecos = t;
    if (!(t = strchr(t, ':')))
	return NULL;
    *t++ = 0;

    mcx->pw.pw_dir = t;
    if (!(t = strchr(t, ':')))
	return NULL;
    *t++ = 0;

    mcx->pw.pw_shell = t;
    if ((t = strchr(t, '\n')))
	*t = 0;

    return &mcx->pw;
}

static struct passwd *get_pwent(mavis_ctx * mcx, int fn, char *s)
{
    size_t offset = 0;
    ssize_t inlength;
    char *linestart = mcx->inbuf;
    char *lineend;
    ssize_t slen = strlen(s);
    s[slen++] = ':';		/* replace terminating \0 with : */

    while ((inlength = Read(fn, mcx->inbuf + offset, sizeof(mcx->inbuf) - 1 - offset)) > 0) {
	inlength += offset;
	mcx->inbuf[inlength] = 0;
	linestart = mcx->inbuf;

	while ((lineend = strchr(linestart, '\n'))) {
	    *lineend = 0;

	    if (!strncmp(s, linestart, slen)) {
		struct passwd *pw = parse_pwent(mcx, linestart);
		s[slen - 1] = 0;
		return pw;
	    }

	    linestart = lineend + 1;
	}

	offset = mcx->inbuf + inlength - linestart;
	if (offset)
	    memmove(mcx->inbuf, linestart, offset);
    }

    s[slen - 1] = 0;
    return NULL;
}

#define HAVE_mavis_send_in
static int mavis_send_in(mavis_ctx * mcx, av_ctx ** ac)
{
    struct passwd *pw;
    char *t, *u, *p, *m;
    char buf[1024];

    t = av_get(*ac, AV_A_TYPE);
    u = av_get(*ac, AV_A_USER);
    p = av_get(*ac, AV_A_PASSWORD);

    if (strcmp(t, AV_V_TYPE_FTP))
	return MAVIS_DOWN;

    /* no VHOST support yet */
    m = av_get(*ac, AV_A_FTP_ANONYMOUS);
    if (m && !strcmp(m, AV_V_BOOL_TRUE))
	return MAVIS_DOWN;

    if (mcx->honour_ftpusers && !valid_user(mcx, u)) {
	av_set(*ac, AV_A_COMMENT, "user found in ftpusers file");
	av_set(*ac, AV_A_RESULT, AV_V_RESULT_FAIL);
	return MAVIS_FINAL;
    }
#ifdef HAVE_SHADOWPWD
    if (!mcx->passwordfile) {
	struct spwd *spw;
	uid_t uid;

	uid = geteuid();
	seteuid(0);
	spw = getspnam(u);
	seteuid(uid);

	if (!spw)
	    return MAVIS_DOWN;

	if (strcmp(spw->sp_pwdp, mcx->crypt(p, spw->sp_pwdp))) {
	    av_set(*ac, AV_A_COMMENT, "password mismatch");
	    av_unset(*ac, AV_A_DBPASSWORD);
	} else
	    av_set(*ac, AV_A_DBPASSWORD, p);
	pw = getpwnam(u);

	if (!pw) {
	    av_set(*ac, AV_A_COMMENT, "user not found in password file");
	    av_set(*ac, AV_A_RESULT, AV_V_RESULT_FAIL);
	    return MAVIS_FINAL;
	}
    } else
#endif				/* HAVE_SHADOWPWD */
    {
	int f;

	f = open(mcx->passwordfile, O_RDONLY);
	if (f < 0) {
	    av_set(*ac, AV_A_COMMENT, "error opening password file");
	    av_set(*ac, AV_A_RESULT, AV_V_RESULT_ERROR);
	    return MAVIS_DOWN;
	}
	pw = get_pwent(mcx, f, u);
	close(f);

	if (!pw)
	    return MAVIS_DOWN;
#undef crypt			/* may be set by openssl include stuff */
	if (strcmp(pw->pw_passwd, mcx->crypt(p, pw->pw_passwd))) {
	    av_set(*ac, AV_A_COMMENT, "password mismatch");
	    av_unset(*ac, AV_A_DBPASSWORD);
	} else
	    av_set(*ac, AV_A_DBPASSWORD, p);
    }

    if (mcx->require_valid_shell && (!pw->pw_shell || !valid_shell(mcx, pw->pw_shell))) {
	av_set(*ac, AV_A_COMMENT, "invalid shell");
	av_set(*ac, AV_A_RESULT, AV_V_RESULT_FAIL);
	return MAVIS_FINAL;
    }
    if (!pw->pw_dir) {
	av_set(*ac, AV_A_COMMENT, "home dir not set");
	av_set(*ac, AV_A_RESULT, AV_V_RESULT_FAIL);
	return MAVIS_FINAL;
    }

    av_setf(*ac, AV_A_UID, "%lu", (u_long) pw->pw_uid);
    av_setf(*ac, AV_A_GID, "%lu", (u_long) pw->pw_gid);

    /* attempt to get supplemental groups */

    av_set(*ac, AV_A_GIDS, groups_getlist(pw->pw_name, pw->pw_gid, buf, sizeof(buf)));

    if (mcx->ftp_chroot) {
	char *tp = strstr(pw->pw_dir, "/./");
	if (tp) {
	    *tp = 0;
	    av_set(*ac, AV_A_HOME, tp + 2);
	} else
	    av_set(*ac, AV_A_HOME, "/");
	av_set(*ac, AV_A_ROOT, pw->pw_dir);
    } else {
	av_set(*ac, AV_A_HOME, pw->pw_dir);
	av_set(*ac, AV_A_ROOT, "/");
    }

    if (mcx->lookup_sslusers)
	lookup_ssluser(mcx, *ac, u);

    return MAVIS_FINAL;
}

static int find_line(int fn, char *s)
{
    char inbuf[8192];
    size_t offset = 0;
    ssize_t inlength;
    char *linestart = inbuf;
    char *lineend;

    while ((inlength = Read(fn, inbuf + offset, sizeof(inbuf) - 1 - offset)) > 0) {
	inlength += offset;
	inbuf[inlength] = 0;
	linestart = inbuf;

	while ((lineend = strchr(linestart, '\n'))) {
	    *lineend = 0;

	    if (!strcmp(s, linestart))
		return -1;

	    linestart = lineend + 1;
	}

	offset = inbuf + inlength - linestart;
	if (offset)
	    memmove(inbuf, linestart, offset);
    }

    return 0;
}

static void find_ssluser(av_ctx * ac, int fn, char *user)
{
    char inbuf[8192];
    size_t offset = 0;
    ssize_t inlength;
    char *linestart = inbuf;
    char *lineend;

    while ((inlength = Read(fn, inbuf + offset, sizeof(inbuf) - 1 - offset)) > 0) {
	inlength += offset;
	inbuf[inlength] = 0;
	linestart = inbuf;

	while ((lineend = strchr(linestart, '\n'))) {
	    *lineend = 0;

	    if (*linestart != '#') {
		char *subj = strchr(linestart, ':');
		if (subj) {
		    char *s = linestart;
		    *subj++ = 0;
		    for (char *t = strtok(s, ","); t; t = strtok(NULL, ","))
			if (!strcmp(user, t)) {
			    char *a = av_get(ac, AV_A_DBCERTSUBJ);
			    if (a)
				av_setf(ac, AV_A_DBCERTSUBJ, "%s\r%s", a, subj);
			    else
				av_set(ac, AV_A_DBCERTSUBJ, subj);
			    break /* out of for-loop */ ;
			}
		}
	    }

	    linestart = lineend + 1;
	}

	offset = inbuf + inlength - linestart;
	if (offset)
	    memmove(inbuf, linestart, offset);
    }
}

/* set AV_A_DBCERTSUBJ if user found */
static void lookup_ssluser(mavis_ctx * mcx, av_ctx * ac, char *user)
{
    int fn = open(mcx->ssluserspath, O_RDONLY);
    if (fn > -1) {
	find_ssluser(ac, fn, user);
	close(fn);
    } else
	logerr("Warning: open(%s)", mcx->ssluserspath);
}

/* return TRUE if user was not found. DEFAULT: TRUE */
static int valid_user(mavis_ctx * mcx, char *user)
{
    int fn, found;

    fn = open(mcx->ftpuserspath, O_RDONLY);
    if (fn < 0)
	return (errno == ENOENT);
    found = find_line(fn, user);
    close(fn);

    return !found;
}

/* return TRUE if shell was found. Default: FALSE */
static int valid_shell(mavis_ctx * mcx, char *shell)
{
    int fn, found;

    fn = open(mcx->shellpath, O_RDONLY);
    if (fn < 0)
	return (errno == ENOENT);
    found = find_line(fn, shell);
    close(fn);

    return found;
}

#define HAVE_mavis_new
static void mavis_new(mavis_ctx * mcx)
{
    mcx->ftp_chroot = -1;
}

#include "mavis_glue.c"
