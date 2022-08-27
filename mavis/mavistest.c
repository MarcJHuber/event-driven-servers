/*
 * mavistest.c
 *
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <time.h>
#include <sysexits.h>
#include <errno.h>
#include <ctype.h>
#include "misc/memops.h"
#include "mavis.h"
#include "misc/version.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

extern int optind, opterr;
extern char *optarg;
static mavis_ctx *mcx = NULL;

static void myparse(struct sym *sym)
{
    while (1) {
	switch (sym->code) {
	case S_closebra:
	case S_eof:
	    return;

	    case_CC_Tokens;
	case S_mavis:
	    sym_get(sym);
	    switch (sym->code) {
	    case S_module:
		parse_mavismodule(&mcx, NULL, sym);
		continue;
	    case S_path:
		parse_mavispath(sym);
		continue;
		case_CC_Tokens;
	    default:
		continue;
	    }
	default:
	    sym_get(sym);
	    if (sym->code == S_openbra) {
		int bc = 1;
		sym_get(sym);
		while (bc) {
		    switch (sym->code) {
		    case S_openbra:
			bc++;
			break;
		    case S_closebra:
			bc--;
			break;
		    case S_eof:
			parse_error(sym, "EOF unexpected");
		    default:
			;
		    }
		    sym_get(sym);
		}
	    }
	}
    }
}

static void usage()
{
    fprintf(stderr,
	    "mavistest [options] <config> <id> <type> <user> [<password>]\n"
	    "\n"
	    "Options:\n"
	    "  -P                  (parse only)\n"
	    "  -d <debuglevel>     (set debug level)\n"
	    "\n"
	    "Valid <type> values: %s, %s\n"
	    "\n" "Sample usage: mavistest -d -1  /usr/local/etc/tac_plus.cfg tac_plus TACPLUS joe p4ssw0rd\n", AV_V_TYPE_FTP, AV_V_TYPE_TACPLUS);
    exit(-1);
}

int main(int argc, char *argv[])
{
    char opt, *optstring = "a:v:d:l:tP";
    int loop = 1;
    int timing = 0;
    time_t start;
    int avt = -1;
    av_ctx *acd = av_new(NULL, NULL);

    init_common_data();

    while ((opt = getopt(argc, argv, optstring)) != CHAREOF)
	switch (opt) {
	case 'l':
	    loop = atoi(optarg);
	    break;
	case 't':
	    timing = 1;
	    break;
	case 'P':
	    common_data.parse_only = 1;
	    break;
	case 'd':
	    common_data.debug = atoi(optarg);
	    break;
	case 'a':
	    if (isdigit((int) (optarg[0])))
		avt = atoi(optarg);
	    else
		avt = av_attribute_to_i(optarg);
	    break;
	case 'v':
	    av_set(acd, avt, optarg);
	    break;
	default:
	    usage();
	}
    argv = &argv[optind];
    argc -= optind;

    if (argc < 3)		// config id user
	usage();

    cfg_read_config(argv[0], myparse, argv[1]);
    if (common_data.parse_only)
	exit(0);

    argv += 1;
    argc--;

    mavis_init(mcx, MAVIS_API_VERSION);

    start = time(NULL);
    while (loop-- > 0) {
	av_ctx *ac = av_new(NULL, NULL);
	av_copy(ac, acd);

	av_setf(ac, AV_A_TIMESTAMP, "mavistest-%d-%ld-%d", (int) getpid(), (long) time(NULL), loop);

	if (!strcasecmp(argv[1], AV_V_TYPE_FTP) && argc == 4) {
	    char *at = strchr(argv[2], '@');
	    av_set(ac, AV_A_TYPE, AV_V_TYPE_FTP);
	    if (at) {
		*at = 0;
		av_set(ac, AV_A_VHOST, at + 1);
		av_set(ac, AV_A_USER, argv[2]);
		*at = '@';
	    } else
		av_set(ac, AV_A_USER, argv[2]);
	    av_set(ac, AV_A_PASSWORD, argv[3]);
	    av_set(ac, AV_A_IPADDR, "0.0.0.0");
	} else if (!strcasecmp(argv[1], AV_V_TYPE_TACPLUS)) {
	    av_set(ac, AV_A_TYPE, AV_V_TYPE_TACPLUS);
	    av_set(ac, AV_A_USER, argv[2]);
	    switch (argc) {
	    case 3:
		av_set(ac, AV_A_TACTYPE, AV_V_TACTYPE_INFO);
		av_set(ac, AV_A_PASSWORD, argv[3]);
		break;
	    case 4:
		av_set(ac, AV_A_TACTYPE, AV_V_TACTYPE_AUTH);
		av_set(ac, AV_A_PASSWORD, argv[3]);
		break;
	    case 5:
		av_set(ac, AV_A_TACTYPE, AV_V_TACTYPE_CHPW);
		av_set(ac, AV_A_PASSWORD, argv[3]);
		av_set(ac, AV_A_PASSWORD_NEW, argv[4]);
		break;
	    default:
		mavis_drop(mcx);
		exit(EX_USAGE);
	    }
	} else {
	    mavis_drop(mcx);
	    exit(EX_USAGE);
	}

	if (!timing) {
	    fprintf(stderr, "\nInput ");
	    av_dump(ac);
	}

	if (mavis_send(mcx, &ac) == MAVIS_FINAL && !timing) {
	    fprintf(stderr, "\nOutput ");
	    av_dump(ac);
	}
    }

    if (timing)
	fprintf(stderr, TIME_T_PRINTF " seconds\n", time(NULL) - start);

    mavis_drop(mcx);

    exit(EX_OK);
}
