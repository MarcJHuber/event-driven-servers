/*
 * radmavis [ -c </path/to/freeradius_client.cfg> ] [group_attritute=<...>] [<option>=<...>] <...>
 *
 * $Id$
 */

#include "misc/sysconf.h"
#include "mavis.h"
#include <stdlib.h>
#include <string.h>
#ifdef DEBUG
#define MAVISDEBUG 1
#undef DEBUG
#endif
#ifdef WITH_RADCLI
#include <radcli/radcli.h>
#define RADLIB "radcli"
#else
#include <freeradius-client.h>
#define RADLIB "freeradius-client"
#endif
#undef DEBUG
#ifdef MAVISDEBUG
#undef MAVISDEBUG
#define DEBUG
#endif
#include "misc/version.h"

static void usage(void)
{
    fprintf(stderr,		// The comments are here to keep indent(1) from messing with code formatting.
	    "\n"		//
	    "Usage: radmavis <options>\n"	//
	    "\n"		//
	    "Options:\n"	//
#ifdef WITH_RADCLI
	    "  -c <configfile>          Path to " RADLIB " configuration file (mandatory)\n"
#else
	    "  -c <configfile>          Path to " RADLIB " configuration file\n"
#endif
	    "  <option>=<value>         Set " RADLIB " option <option> to <value>\n"	//
	    "  group_attribute=<attr>   Use attribute <attr> to determine user groups\n"	//
	    "\n"		//
	    "This program uses the " RADLIB " library from\n"	//
#ifdef WITH_RADCLI
	    "  https://github.com/radcli/radcli\n"
#else
	    "  https://github.com/FreeRADIUS/freeradius-client\n"
#endif
	    "\n"		//
	    "Please have a look there about " RADLIB " configuration syntax.\n"	//
	    "The RADIUS settings section in etc/radiusclient.conf.in might be a good\n"	//
	    "starting point.\n"	//
	    "\n"		//
	    "Version: " VERSION "/" RADLIB "\n"	//
	    "\n"		//
	    "Sample usage:\n"
#ifdef WITH_RADCLI
	    "  radmavis -c /etc/radcli/radiusclient.conf\n"
#else
	    "  radmavis authserver=localhost:1812:mysecret dictionary=/path/to/dictionary\n"
#endif
	    "\n");
    exit(-1);
}

static void set_rc(rc_handle *rh, char *a, char *v)
{
    if (!rc_add_config(rh, a, v, "config", 0))
	return;
    fprintf(stderr, "Unable to set '%s'\n", a);
    exit(-1);
}

int main(int argc, char **argv)
{
    rc_handle *rh = NULL;
    char buf[4096], *user = NULL, *pass = NULL;
    VALUE_PAIR *send = NULL, *received = NULL;
    int group_attribute = -1;
    char *group_attribute_name = NULL;
    char **a = argv;

    if (argc < 2)
	usage();

    rc_openlog("radmavis");

    while (*a && strcmp(*a, "-c"))
	a++;
    if (*a)
	a++;

    char *cfg = *a;
#if defined(WITH_RADCLI)
    if (!cfg) {
	char *cfgs[] = { "/etc/radcli/radiusclient.conf", "/usr/local/etc/radcli/radiusclient.conf", NULL };
	for (char **c = cfgs; *c && !cfg; c++)
	    if (!access(*c, R_OK))
		cfg = *c;
	if (cfg)
	    fprintf(stderr, "Configuration file found: %s\n", cfg);
	else {
	    fprintf(stderr, "No configuration file found, exiting.\n");
	    exit(-1);
	}
    }
#endif

    if (cfg) {
	rh = rc_read_config(cfg);
	if (!rh) {
	    fprintf(stderr, "Parsing %s failed.\n", cfg);
	    exit(-1);
	}
    }
#ifndef WITH_RADCLI
    if (!rh) {
	// set some defaults
	rh = rc_new();
	rh = rc_config_init(rh);

	set_rc(rh, "auth_order", "radius");
	set_rc(rh, "login_tries", "4");
	set_rc(rh, "radius_retries", "3");
	set_rc(rh, "radius_timeout", "5");
	set_rc(rh, "radius_deadtime", "10");

	char *dicts[] = { "/etc/radiusclient/dictionary", "/usr/local/etc/radiusclient/dictionary", NULL };
	for (char **d = dicts; *d; d++)
	    if (!access(*d, R_OK)) {
		set_rc(rh, "dictionary", *d);
		break;
	    }
    }
#endif
#if defined(WITH_RADCLI) && (RADCLI_VERSION_NUMBER > 0x010209)
    rc_apply_config(rh);
#endif

    a = argv;
    a++;
    while (*a) {
	char *eq = strchr(*a, '=');
	if (eq) {
	    *eq = 0;
	    if (!strcmp(*a, "group_attribute")) {
		group_attribute_name = strdup(eq + 1);
		group_attribute = atoi(group_attribute_name);
	    } else		// assume this is a freeradius-client option:
		set_rc(rh, *a, eq + 1);
	    *eq = '=';
	} else if (!strcmp(*a, "-h")) {
	    usage();
	} else if (!strcmp(*a, "-c")) {	// skip argument, processed before
	    a++;
	} else {
	    fprintf(stderr, "Unable to parse '%s'\n", *a);
	    usage();
	}
	a++;
    }

    if (rc_read_dictionary(rh, rc_conf_str(rh, "dictionary"))) {
	fprintf(stderr, "reading %s failed\n", rc_conf_str(rh, "dictionary"));
	return ERROR_RC;
    }

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
	    default:;
	    }
	} else if (!strcmp(buf, "=\n")) {
	    uint32_t service;
	    int result;
	    if (user && pass) {
		rc_avpair_add(rh, &send, PW_USER_NAME, user, -1, 0);
		rc_avpair_add(rh, &send, PW_USER_PASSWORD, pass, -1, 0);
		service = PW_AUTHENTICATE_ONLY;
		rc_avpair_add(rh, &send, PW_SERVICE_TYPE, &service, -1, 0);
		*buf = 0;
		result = rc_auth(rh, 0, send, &received, buf);
		if (*buf)
		    printf("%d %s\n", AV_A_COMMENT, buf);
		if (received && (group_attribute_name || group_attribute > -1)) {
		    // check for group attributes
		    int mc = 0;
		    VALUE_PAIR *r = received;
		    while (r) {
			if (!strcmp(r->name, group_attribute_name) || ((int) group_attribute == (int) r->attribute)) {
			    if (strncmp("CACS:", r->strvalue, 4)) {
				if (!mc)
				    printf("%d ", AV_A_TACMEMBER);
				else
				    printf(",");
				printf("%s", r->strvalue);
				mc++;
			    }
			}
			r = r->next;
		    }
		    if (mc)
			printf("\n");
		}

	    } else
		result = REJECT_RC;

	    switch (result) {
	    case OK_RC:
		printf("%d 1\n", AV_A_PASSWORD_ONESHOT);
		printf("%d %s\n", AV_A_DBPASSWORD, pass);
		printf("%d %s\n", AV_A_RESULT, AV_V_RESULT_OK);
		printf("=%d\n", MAVIS_FINAL);
		break;
	    case REJECT_RC:
		printf("%d %s\n", AV_A_RESULT, AV_V_RESULT_FAIL);
		printf("=%d\n", MAVIS_FINAL);
		break;
	    case TIMEOUT_RC:
	    case BADRESP_RC:
	    case ERROR_RC:
		printf("%d %s\n", AV_A_RESULT, AV_V_RESULT_ERROR);
		printf("=%d\n", MAVIS_TIMEOUT);
		break;
	    default:
		printf("=%d\n", MAVIS_DOWN);
		break;
	    }

	    fflush(stdout);

	    rc_avpair_free(send);
	    rc_avpair_free(received);
	    send = NULL, received = NULL;
	    if (user) {
		free(user);
		user = NULL;
	    }
	    if (pass) {
		free(pass);
		pass = NULL;
	    }
	} else {
	    fprintf(stderr, "%s: Protocol violation. Exiting.\n", argv[0]);
	    exit(-1);
	}
    }

    exit(-1);
}
