/*
 * pammavis-mt [ -s service ]
 '
 ' multithread-enabled pammavis variant, for use with external-mt
 *
 * $Id$
 */

#include "misc/sysconf.h"
#include <string.h>
#include "mavis.h"
#include "misc/memops.h"
#include <pwd.h>
#include <sys/types.h>
#include <grp.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#else
#include <pam/pam_appl.h>
#endif
#include "groups.h"
#include "misc/version.h"

static char *service = "mavis";
static void usage(void)
{
    fprintf(stderr,		// The comments are here to keep indent(1) from messing with code formatting.
	    "\n"		//
	    "Usage: pammavis-mt <options>]\n"	//
	    "\n"		//
	    "Options:\n"	//
	    "  -s <service>     PAM service to use (default: mavis)\n"	//
	    "  -o <string>      generate test input on stdout\n"	//
	    "\n");
    exit(-1);
}

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
    struct pam_response *reply = calloc(num_msg, sizeof(struct pam_response));

    for (count = 0; count < num_msg; count++)
	switch (msg[count]->msg_style) {
	case PAM_PROMPT_ECHO_ON:
	    reply[count].resp = strdup(((struct appdata *) appdata_ptr)->user);
	    break;
	case PAM_PROMPT_ECHO_OFF:
	    reply[count].resp = strdup(((struct appdata *) appdata_ptr)->pass);
	case PAM_TEXT_INFO:
	    break;
	default:
	    while (--count > -1)
		free(reply[count].resp);
	    free(reply);
	    return PAM_CONV_ERR;	/* won't happen */
	}

    *response = reply;
    return PAM_SUCCESS;
}

static int check_auth(char *user, char *pass, int chpass, const char **pamerr)
{
    struct pam_conv pc;
    struct appdata ad;
    pam_handle_t *ph;
    int res;

    ad.user = user, ad.pass = pass;

    memset(&pc, 0, sizeof(struct pam_conv));
    pc.conv = &pam_conv;
    pc.appdata_ptr = &ad;

    res = pam_start(service, user, &pc, &ph);

    if (res != PAM_SUCCESS && res != PAM_AUTHTOK_EXPIRED)
	return 0;

    res = chpass ? pam_chauthtok(ph, PAM_SILENT) : pam_authenticate(ph, PAM_SILENT);

    /* check whether user account is to be considered healthy */
    if (res == PAM_SUCCESS)
	res = pam_acct_mgmt(ph, PAM_SILENT);

    *pamerr = pam_strerror(ph, res);

    pam_end(ph, res);

    return res;
}

static pthread_mutex_t mutex_lock;

static void av_write(av_ctx * ac, uint32_t result)
{
    size_t len = av_array_to_char_len(ac);
    char *buf = alloca(len + sizeof(struct mavis_ext_hdr_v1));
    len = av_array_to_char(ac, buf + sizeof(struct mavis_ext_hdr_v1), len, NULL);

    struct mavis_ext_hdr_v1 *h = (struct mavis_ext_hdr_v1 *) buf;
    h->magic = htonl(MAVIS_EXT_MAGIC_V1);
    h->body_len = htonl((uint32_t) len);
    h->result = htonl(result);

    len += sizeof(struct mavis_ext_hdr_v1);
    pthread_mutex_lock(&mutex_lock);
    write(1, buf, len);
    pthread_mutex_unlock(&mutex_lock);
    av_free(ac);
}

static void *run_thread(void *arg)
{
    av_ctx *ac = (av_ctx *) arg;
    const char *pamerr = NULL;
    char *user = av_get(ac, AV_A_USER);
    char *pass = av_get(ac, AV_A_PASSWORD);
    int res = check_auth(user, pass, 0, &pamerr);

    if ((res == PAM_SUCCESS || res == PAM_AUTHTOK_EXPIRED) && !strcmp(av_get(ac, AV_A_TACTYPE), AV_V_TACTYPE_CHPW)) {
	pass = av_get(ac, AV_A_PASSWORD_NEW);
	res = check_auth(user, pass, 1, &pamerr);
    }

    switch (res) {
    case PAM_SUCCESS:
	av_set(ac, AV_A_DBPASSWORD, pass);
	av_set(ac, AV_A_RESULT, AV_V_RESULT_OK);
	break;
    default:
	if (pamerr)
	    av_set(ac, AV_A_COMMENT, (char *) pamerr);
	av_set(ac, AV_A_RESULT, AV_V_RESULT_FAIL);
	break;
    }
    av_write(ac, MAVIS_FINAL);
    return NULL;
}

static void generate_test_output(char *arg)
{
    char *s = alloca(strlen(arg) + 1);
    char *t = s;

    while (*arg) {
	if (*arg == '\\' && *(arg + 1) == 'n')
	    *t++ = '\n', arg++;
	else if (*arg == '\\' && *(arg + 1) == 'r')
	    *t++ = '\r', arg++;
	else
	    *t++ = *arg;
	arg++;
    }
    *t = 0;
    av_ctx *ac = av_new(NULL, NULL);
    av_char_to_array(ac, s, NULL);
    av_write(ac, MAVIS_FINAL);
}

int main(int argc, char **argv)
{
    extern char *optarg;
    extern int optind;
    int c;
    char buf[4096];
    struct mavis_ext_hdr_v1 hdr;

    if (pthread_mutex_init(&mutex_lock, NULL))
	fprintf(stderr, "pthread_mutex_init() failed, expect trouble\n");

    while ((c = getopt(argc, argv, "s:o:")) != EOF)
	switch (c) {
	case 's':
	    service = optarg;
	    break;
	case 'o':
	    generate_test_output(optarg);
	    exit(EX_OK);
	default:
	    usage();
	    exit(EX_OK);
	}

    if (argv[optind])
	usage();

    if (snprintf(buf, sizeof(buf), "/etc/pam.d/%s", service) < (int) sizeof(buf)) {
	if (access(buf, F_OK))
	    fprintf(stderr,
		    "Service file %s for PAM service %s does not exist, you may need to specify "
		    "a valid service using the '-s <service>' option.\n", buf, service);
    }

    if (geteuid())
	fprintf(stderr, "Not running as root, PAM may or may not work as expected.\n");

    while (1) {
	size_t hdr_off = 0;
	while (sizeof(struct mavis_ext_hdr_v1) != hdr_off) {
	    int len = read(0, (char *) &hdr + hdr_off, sizeof(struct mavis_ext_hdr_v1) - hdr_off);
	    if (len < 1) {
		fprintf(stderr, "Short read (header).\n");
		exit(-1);
	    }
	    hdr_off += len;
	}
	if (ntohl(hdr.magic) != MAVIS_EXT_MAGIC_V1) {
	    fprintf(stderr, "Bad magic.\n");
	    exit(-1);
	}
	size_t len = ntohl(hdr.body_len);
	char *b = calloc(1, len + 1);
	size_t off = 0;
	while (len - off > 0) {
	    size_t nlen = read(0, b + off, len - off);
	    if (nlen < 1) {
		fprintf(stderr, "Short read (body).\n");
		exit(1);
	    }
	    off += nlen;
	}

	av_ctx *ac = av_new(NULL, NULL);
	av_char_to_array(ac, b, NULL);
	char *user = av_get(ac, AV_A_USER);
	if (!user)
	    exit(-1);
	struct passwd *pw = getpwnam(user);
	char *tactype = av_get(ac, AV_A_TACTYPE);
	if (!tactype || !pw) {
	    av_write(ac, MAVIS_DOWN);
	} else if (!av_get(ac, AV_A_PASSWORD) && !strcmp(tactype, AV_V_TACTYPE_AUTH)) {
	    av_set(ac, AV_A_RESULT, AV_V_RESULT_FAIL);
	    av_write(ac, MAVIS_FINAL);
	} else if ((!av_get(ac, AV_A_PASSWORD) || !av_get(ac, AV_A_PASSWORD_NEW)) && !strcmp(tactype, AV_V_TACTYPE_CHPW)) {
	    av_set(ac, AV_A_RESULT, AV_V_RESULT_FAIL);
	    av_write(ac, MAVIS_FINAL);
	} else {
	    av_setf(ac, AV_A_UID, "%lu", (u_long) pw->pw_uid);
	    av_setf(ac, AV_A_GID, "%lu", (u_long) pw->pw_gid);
	    av_set(ac, AV_A_GIDS, groups_getlist(pw->pw_name, pw->pw_gid, buf, sizeof(buf)));
	    if (pw->pw_dir)
		av_set(ac, AV_A_HOME, pw->pw_dir);
	    if (pw->pw_shell)
		av_set(ac, AV_A_SHELL, pw->pw_shell);

	    if (!strcmp(tactype, AV_V_TACTYPE_INFO)) {
		av_set(ac, AV_A_RESULT, AV_V_RESULT_OK);
		av_write(ac, MAVIS_FINAL);
	    } else {
		pthread_t thread;
		pthread_attr_t thread_attr;
		pthread_attr_init(&thread_attr);
		char *fname = "pthread_create";
		int res = pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
		if (res)
		    fname = "pthread_attr_setdetachstate";
		else
		    res = pthread_create(&thread, &thread_attr, run_thread, ac);
		if (res) {
		    char *err = strerror(res);
		    av_setf(ac, AV_A_COMMENT, "%s(): %s%s[%d]", fname, err ? err : "", err ? " " : "", res);
		    fprintf(stderr, "%s\n", av_get(ac, AV_A_COMMENT));
		    av_set(ac, AV_A_RESULT, AV_V_RESULT_ERROR);
		    av_write(ac, MAVIS_FINAL);
		}
	    }
	}
	free(b);
    }
    exit(EX_OK);
}
