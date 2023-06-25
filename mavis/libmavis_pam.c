/*
 * libmavis_pam.c
 *
 * Pluggable Authentication Modules support for MAVIS
 *
 * (C)2000-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#define MAVIS_name "pam"

#include "misc/sysconf.h"
#include "misc/strops.h"
#include "misc/memops.h"
#include "log.h"
#include "debug.h"
#include <pwd.h>
#include <sys/types.h>
#include <grp.h>
#include <errno.h>
#include <unistd.h>
#include <dlfcn.h>
#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#else
#include <pam/pam_appl.h>
#endif
#include "groups.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

#define MAVIS_CTX_PRIVATE	\
	int initialized;	\
	int ftp_chroot;		\
	char *service;

#include "mavis.h"

struct appdata {
    char *user;
    char *pass;
};

/*
 * The conversation function. Alas, OSF-RFC 86.0 doesn't go into
 * much detail, so this is largely based upon linux-pam documentation.
 */
static int pam_conv(int num_msg, PAM_CONV_ARG2_TYPE ** msg, struct pam_response **response, void *appdata_ptr)
{
    int count;
    struct pam_response *reply = Xcalloc(num_msg, sizeof(struct pam_response));

    for (count = 0; count < num_msg; count++)
	switch (msg[count]->msg_style) {
	case PAM_PROMPT_ECHO_ON:
	    reply[count].resp = Xstrdup(((struct appdata *) appdata_ptr)->user);
	    break;
	case PAM_PROMPT_ECHO_OFF:
	    reply[count].resp = Xstrdup(((struct appdata *) appdata_ptr)->pass);
	case PAM_TEXT_INFO:
	    break;
	default:
	    while (--count > -1)
		Xfree(&reply[count].resp);
	    Xfree(&reply);
	    return PAM_CONV_ERR;	/* won't happen */
	}

    *response = reply;
    return PAM_SUCCESS;
}

static int check_auth(mavis_ctx * mcx, char *user, char *pass)
{
    struct pam_conv pc;
    struct appdata ad;
    pam_handle_t *ph;
    int res;

    ad.user = user, ad.pass = pass;

    memset(&pc, 0, sizeof(struct pam_conv));
    pc.conv = &pam_conv;
    pc.appdata_ptr = &ad;

    res = pam_start(mcx->service, user, &pc, &ph);

    if (res != PAM_SUCCESS)
	return 0;

    res = pam_authenticate(ph, PAM_SILENT);

    /* check whether user account is to be considered healthy */
    if (res == PAM_SUCCESS)
	res = pam_acct_mgmt(ph, PAM_SILENT);

    pam_end(ph, res);

    return res == PAM_SUCCESS;
}

#define HAVE_mavis_init_in
static int mavis_init_in(mavis_ctx * mcx)
{
    DebugIn(DEBUG_MAVIS);
    if (!mcx->initialized) {
	mcx->initialized++;
	if (!mcx->service)
	    mcx->service = Xstrdup("mavis");
	if (geteuid())
	    logmsg("Warning: PAM module may require root privileges");
    }
    DebugOut(DEBUG_MAVIS);
    return MAVIS_INIT_OK;
}

/*
chroot = yes | no service = name
*/
#define HAVE_mavis_parse_in
static int mavis_parse_in(mavis_ctx * mcx, struct sym *sym)
{
    while (1) {
	switch (sym->code) {
	case S_script:
	    mavis_script_parse(mcx, sym);
	    continue;
	case S_chroot:
	    sym_get(sym);
	    parse(sym, S_equal);
	    mcx->ftp_chroot = parse_bool(sym);
	    continue;
	case S_service:
	    sym_get(sym);
	    parse(sym, S_equal);
	    strset(&mcx->service, sym->buf);
	    sym_get(sym);
	    continue;
	case S_eof:
	case S_closebra:
	    return MAVIS_CONF_OK;
	case S_action:
	    mavis_module_parse_action(mcx, sym);
	    continue;
	default:
	    parse_error_expect(sym, S_script, S_service, S_chroot, S_action, S_closebra, S_unknown);
	}
    }
}


#define HAVE_mavis_drop_in
static void mavis_drop_in(mavis_ctx * mcx)
{
    Xfree(&mcx->service);
}

#define HAVE_mavis_send_in
static int mavis_send_in(mavis_ctx * mcx, av_ctx ** ac)
{
    struct passwd *pw;
    char *t, *u, *p, *m;
    uid_t uid;
    int res;

    t = av_get(*ac, AV_A_TYPE);
    u = av_get(*ac, AV_A_USER);
    p = av_get(*ac, AV_A_PASSWORD);

    if (strcmp(t, AV_V_TYPE_FTP))
	return MAVIS_DOWN;

/* no VHOST support yet */
    m = av_get(*ac, AV_A_FTP_ANONYMOUS);
    if (m && !strcmp(m, AV_V_BOOL_TRUE))
	return MAVIS_DOWN;

    if (!(pw = getpwnam(u)))
	return MAVIS_DOWN;

    if (!pw->pw_dir) {
	av_set(*ac, AV_A_COMMENT, "home dir not set");
	av_set(*ac, AV_A_RESULT, AV_V_RESULT_FAIL);
	return MAVIS_FINAL;
    }

    uid = geteuid();
    UNUSED_RESULT(seteuid(0));
    res = check_auth(mcx, u, p);
    UNUSED_RESULT(seteuid(uid));

    /* The PAM routines may have spoiled our logging identity. */
    logopen();

    if (res) {
	char buf[1024];

	av_set(*ac, AV_A_DBPASSWORD, p);

	av_setf(*ac, AV_A_UID, "%lu", (u_long) pw->pw_uid);
	av_setf(*ac, AV_A_GID, "%lu", (u_long) pw->pw_gid);

	/* attempt to get supplemental groups */

	av_set(*ac, AV_A_GIDS, groups_getlist(pw->pw_name, pw->pw_gid, buf, sizeof(buf)));

	if (mcx->ftp_chroot) {
	    t = strstr(pw->pw_dir, "/./");
	    if (t) {
		*t = 0;
		av_set(*ac, AV_A_HOME, t + 2);
	    } else
		av_set(*ac, AV_A_HOME, "/");
	    av_set(*ac, AV_A_ROOT, pw->pw_dir);
	} else {
	    av_set(*ac, AV_A_HOME, pw->pw_dir);
	    av_set(*ac, AV_A_ROOT, "/");
	}
    } else
	av_set(*ac, AV_A_RESULT, AV_V_RESULT_FAIL);
    return MAVIS_FINAL;
}

#define HAVE_mavis_new
static void mavis_new(mavis_ctx * pc)
{
    pc->ftp_chroot = -1;
}

#include "mavis_glue.c"
