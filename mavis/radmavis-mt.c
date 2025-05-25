/*
 * radmavis-mt [ -s service ]
 '
 ' multithread-enabled radmavis variant, for use with external-mt
 *
 * $Id$
 */

#include "misc/sysconf.h"
#include "mavis.h"
#include <stdlib.h>
#include <sysexits.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#ifdef DEBUG
#define MAVISDEBUG 1
#undef DEBUG
#endif
#ifdef WITH_RADCLI
#include <radcli/radcli.h>
#else
#include <freeradius-client.h>
#endif
#undef DEBUG
#ifdef MAVISDEBUG
#undef MAVISDEBUG
#define DEBUG
#endif
#include "misc/version.h"

#define TRISTATE_DUNNO  0
#define TRISTATE_YES    1
#define TRISTATE_NO     2
static int is_mt = TRISTATE_DUNNO;

static void usage(void)
{
    fprintf(stderr,		// The comments are here to keep indent(1) from messing with code formatting.
	    "\n"		//
	    "Usage: radmavis-mt <options>\n"	//
	    "\n"		//
	    "Options:\n"	//
#ifdef WITH_RADCLI
	    "  -c <configfile>          Path to radcli configuration file (mandatory)\n"	//
#else
	    "  -c <configfile>          Path to freeradius-client configuration file\n"	//
#endif
	    "  group_attribute=<attr>   Use attribute <attr> to determine user groups\n"	//
	    "  <option>=<value>         Set freeradius-client option <option> to <value>\n"	//
	    "\n"		//
#ifdef WITH_RADCLI
	    "This program uses the radcli library from\n"	//
	    "  https://github.com/radcli/radcli\n"	//
	    "\n"		//
	    "Please have a look there about radcli configuration syntax.\n"	//
#else
	    "This program uses the freeradius-client library from\n"	//
	    "  https://github.com/FreeRADIUS/freeradius-client\n"	//
	    "\n"		//
	    "Please have a look there about freeradius-client configuration syntax.\n"	//
#endif
	    "The RADIUS settings section in etc/radiusclient.conf.in might be a good\n"	//
	    "starting point.\n"	//
	    "\n" "Sample usage:\n"	//
	    "  radmavis-mt authserver=localhost:1812:mysecret dictionary=/path/to/dictionary\n"	//
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

static pthread_mutex_t mutex_lock;

static void av_write(av_ctx *ac, uint32_t result)
{
    size_t len = av_array_to_char_len(ac);
    char *buf = alloca(len + sizeof(struct mavis_ext_hdr_v1));
    if (is_mt == TRISTATE_YES) {
	len = av_array_to_char(ac, buf + sizeof(struct mavis_ext_hdr_v1), len, NULL);

	struct mavis_ext_hdr_v1 *h = (struct mavis_ext_hdr_v1 *) buf;
	h->magic = htonl(MAVIS_EXT_MAGIC_V1);
	h->body_len = htonl((uint32_t) len);
	h->result = htonl(result);

	len += sizeof(struct mavis_ext_hdr_v1);
	pthread_mutex_lock(&mutex_lock);
	write(1, buf, len);
	pthread_mutex_unlock(&mutex_lock);
    } else {
	len = av_array_to_char(ac, buf, len, NULL);
	len += snprintf(buf + len, sizeof(struct mavis_ext_hdr_v1), "=%u\n", result);
	write(1, buf, len);
    }
    av_free(ac);
}

static rc_handle *rh = NULL;
static int group_attribute = -1;
static char *group_attribute_name = NULL;

static void *run_thread(void *arg)
{
    char buf[4096];
    *buf = 0;
    av_ctx *ac = (av_ctx *) arg;

    int service = PW_AUTHENTICATE_ONLY;
    VALUE_PAIR *send = NULL, *received = NULL;
    rc_avpair_add(rh, &send, PW_SERVICE_TYPE, &service, -1, 0);
    rc_avpair_add(rh, &send, PW_USER_NAME, av_get(ac, AV_A_USER), -1, 0);
    rc_avpair_add(rh, &send, PW_USER_PASSWORD, av_get(ac, AV_A_PASSWORD), -1, 0);

    int result = rc_auth(rh, 0, send, &received, buf);
    if (*buf)
	av_set(ac, AV_A_COMMENT, buf);
    if (received) {
	if ((group_attribute_name || group_attribute > -1)) {
	    int remaining = sizeof(buf) - 10;
	    char *b = buf;
	    *b = 0;

	    VALUE_PAIR *r = received;
	    while (r) {
		if (!strcmp(r->name, group_attribute_name) || ((int) group_attribute == (int) r->attribute)) {
		    int len = snprintf(b, remaining, "%s\"", *buf ? "," : "");
		    if (len > 0) {
			b += len;
			remaining -= len;
			len = snprintf(b, remaining, "%s\"", r->strvalue);
		    }
		    if (len < 0) {
			result = ERROR_RC;
			*buf = 0;
			break;
		    }
		    b += len;
		    remaining -= len;
		}
		r = r->next;
	    }
	    if (*buf)
		av_set(ac, AV_A_TACMEMBER, buf);
	}
    } else
	result = REJECT_RC;

    rc_avpair_free(send);
    rc_avpair_free(received);

    int res = MAVIS_FINAL;

    switch (result) {
    case OK_RC:
	av_set(ac, AV_A_PASSWORD_ONESHOT, "1");
	av_set(ac, AV_A_DBPASSWORD, av_get(ac, AV_A_PASSWORD));
	av_set(ac, AV_A_RESULT, AV_V_RESULT_OK);
	break;
    case REJECT_RC:
	av_set(ac, AV_A_RESULT, AV_V_RESULT_FAIL);
	break;
    case TIMEOUT_RC:
	res = MAVIS_TIMEOUT;
    default:
	av_set(ac, AV_A_RESULT, AV_V_RESULT_ERROR);
	break;
    }

    av_write(ac, res);
    return NULL;
}

int main(int argc, char **argv)
{
    extern char *optarg;
    extern int optind;
    struct mavis_ext_hdr_v1 hdr;
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
	exit(-1);
    }

    while (1) {
	size_t hdr_off = 0;
	av_ctx *ac = NULL;

	if (is_mt != TRISTATE_NO) {
	    while (sizeof(struct mavis_ext_hdr_v1) != hdr_off) {
		int len = read(0, (char *) &hdr + hdr_off, sizeof(struct mavis_ext_hdr_v1) - hdr_off);
		if (len < 1) {
		    exit(-1);
		}
		hdr_off += len;
	    }
	}

	if (is_mt != TRISTATE_NO && ntohl(hdr.magic) == MAVIS_EXT_MAGIC_V1) {
	    if (is_mt == TRISTATE_DUNNO) {
		if (pthread_mutex_init(&mutex_lock, NULL))
		    fprintf(stderr, "pthread_mutex_init() failed, expect trouble\n");
		is_mt = TRISTATE_YES;
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
	    ac = av_new(NULL, NULL);
	    av_char_to_array(ac, b, NULL);
	    free(b);
	} else {
	    if (is_mt == TRISTATE_YES) {
		fprintf(stderr, "Bad magic.\n");
		exit(-1);
	    } else {
		static char *buf = NULL;
#define BUFSIZE 4095
		if (!buf)
		    buf = calloc(1, BUFSIZE + 1);
		static size_t off = 0;
		if (is_mt == TRISTATE_DUNNO) {
		    memcpy(buf, &hdr, sizeof(hdr));
		    off = sizeof(hdr);
		    fcntl(0, F_SETFL, O_NONBLOCK);
		    is_mt = TRISTATE_NO;
		}
		struct pollfd pfd = {.events = POLLIN };
		char *end = strstr(buf, "\n=\n");
		while (end || (1 == poll(&pfd, 1, -1) && off < BUFSIZE)) {
		    if (!end) {
			ssize_t len = read(0, buf + off, BUFSIZE - off);
			if (len < 1) {
			    exit(-1);
			}
			off += len;
			buf[off] = 0;
			end = strstr(buf, "\n=\n");
		    }
		    if (end) {
			*(end + 1) = 0;
			ac = av_new(NULL, NULL);
			av_char_to_array(ac, buf, NULL);
			end += 3;
			memmove(buf, end, off - (end - buf) + 1);
			off -= end - buf;
			break;
		    }
		}
		if (!ac) {
		    fprintf(stderr, "Legacy read buffer too small\n");
		    exit(-1);
		}
	    }
	}

	char *tactype = av_get(ac, AV_A_TACTYPE);
	if (!tactype || strcmp(tactype, AV_V_TACTYPE_AUTH)) {
	    av_write(ac, MAVIS_DOWN);
	} else if (!av_get(ac, AV_A_PASSWORD) && !strcmp(tactype, AV_V_TACTYPE_AUTH)) {
	    av_set(ac, AV_A_RESULT, AV_V_RESULT_FAIL);
	    av_write(ac, MAVIS_FINAL);
	} else if (is_mt == TRISTATE_YES) {
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
	} else {
	    run_thread(ac);
	}
    }
    exit(EX_OK);
}
