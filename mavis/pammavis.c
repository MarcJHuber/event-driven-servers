/*
 * pammavis [ -s service ]
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
	    "Usage: pammavis <options>]\n"	//
	    "\n"		//
	    "Options:\n"	//
	    "  -s <service>     PAM service to use (default: mavis)\n"	//
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

static int check_auth(char *user, char *pass, const char **pamerr)
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

    if (res != PAM_SUCCESS)
	return 0;

    res = pam_authenticate(ph, PAM_SILENT);

    /* check whether user account is to be considered healthy */
    if (res == PAM_SUCCESS)
	res = pam_acct_mgmt(ph, PAM_SILENT);

    *pamerr = pam_strerror(ph, res);

    pam_end(ph, res);

    return res;
}

static int print_credentials(char *user)
{
    struct passwd *pw = getpwnam(user);
    if (pw) {
	char buf[2048];
	printf("%d %lu\n", AV_A_UID, (u_long) pw->pw_uid);
	printf("%d %lu\n", AV_A_GID, (u_long) pw->pw_gid);
	printf("%d %s\n", AV_A_GIDS, groups_getlist(pw->pw_name, pw->pw_gid, buf, sizeof(buf)));
	if (pw->pw_dir)
	    printf("%d %s\n", AV_A_HOME, pw->pw_dir);
	if (pw->pw_shell)
	    printf("%d %s\n", AV_A_SHELL, pw->pw_shell);
	return 0;
    }
    return -1;
}

int main(int argc, char **argv)
{
    extern char *optarg;
    extern int optind;
    int c;

    char buf[4096], *user = NULL, *pass = NULL;
    int tact_info = 0;

    while ((c = getopt(argc, argv, "s:")) != EOF)
	switch (c) {
	case 's':
	    service = optarg;
	    break;
	default:
	    usage();
	    exit(EX_OK);
	}

    if (argv[optind])
	usage();

    while (fgets(buf, sizeof(buf), stdin)) {
	int mavis_attr;
	char mavis_val[4096];
	if (2 == sscanf(buf, "%d%[^\n]\n", &mavis_attr, mavis_val) && *mavis_val) {
	    printf("%s", buf);
	    switch (mavis_attr) {
	    case AV_A_USER:
		user = strdup(mavis_val + 1);
		break;
	    case AV_A_PASSWORD:
		pass = strdup(mavis_val + 1);
		break;
	    case AV_A_TACTYPE:
		tact_info = !strcmp(mavis_val + 1, AV_V_TACTYPE_INFO);
		break;
	    default:;
	    }
	} else if (!strcmp(buf, "=\n")) {
	    *buf = 0;

	    if (pass) {
		const char *pamerr = NULL;
		int res = getpwnam(user) ? check_auth(user, pass, &pamerr) : PAM_USER_UNKNOWN;
		switch (res) {
		case PAM_SUCCESS:
		    if (print_credentials(user))	// not found by getpwnam()
			printf("=%d\n", MAVIS_DOWN);
		    else
			printf("%d %s\n%d %s\n=%d\n", AV_A_RESULT, AV_V_RESULT_OK, AV_A_DBPASSWORD, pass, MAVIS_FINAL);
		    break;
		case PAM_USER_UNKNOWN:
		    printf("=%d\n", MAVIS_DOWN);
		    break;
		default:
		    if (pamerr)
			printf("%d %s\n", AV_A_COMMENT, pamerr);
		    printf("%d %s\n=%d\n", AV_A_RESULT, AV_V_RESULT_FAIL, MAVIS_FINAL);
		    break;
		}
	    } else {
		if (print_credentials(user))
		    printf("=%d\n", MAVIS_DOWN);
		else {
		    if (tact_info)
			printf("%d %s\n", AV_A_RESULT, AV_V_RESULT_OK);

		    printf("=%d\n", MAVIS_FINAL);
		}
	    }

	    fflush(stdout);

	    if (user) {
		free(user);
		user = NULL;
	    }
	    if (pass) {
		free(pass);
		pass = NULL;
	    }
	    tact_info = 0;
	} else {
	    fprintf(stderr, "%s: Protocol violation. Exiting.\n", argv[0]);
	    exit(-1);
	}
    }

    exit(-1);
}
