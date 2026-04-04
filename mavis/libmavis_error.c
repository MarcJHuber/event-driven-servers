/*
 * libmavis_error.c
 *
 * Backend module for handling MAVIS errors
 *
 * (C)2026 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * mavis module = error {
 *     threshold = 3 # convert ERROR to FAIL until threshold is reached
 *     file = /var/tmp/mavis_failure # use this file for counting
 * }
 '
 * $Id$
 */

#define MAVIS_name "error"

#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/file.h>
#include <unistd.h>

#include "debug.h"
#include "log.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

#define MAVIS_CTX_PRIVATE	\
  char *path;			\
  int threshold;

#include "mavis.h"

#define HAVE_mavis_parse_in
static int mavis_parse_in(mavis_ctx *mcx, struct sym *sym)
{
    while (1) {
	switch (sym->code) {
	case S_script:
	    mavis_script_parse(mcx, NULL, sym);
	    continue;
	case S_file:
	    sym_get(sym);
	    parse(sym, S_equal);
	    mcx->path = strdup(sym->buf);
	    sym_get(sym);
	    continue;
	case S_threshold:
	    sym_get(sym);
	    parse(sym, S_equal);
	    mcx->threshold = parse_int(sym);
	    continue;
	case S_eof:
	case S_closebra:
	    if (!mcx->path)
		logmsg("Warning: %s: module lacks 'file' definition", MAVIS_name);
	    return MAVIS_CONF_OK;
	case S_action:
	    mavis_module_parse_action(mcx, sym);
	    continue;
	default:
	    parse_error_expect(sym, S_script, S_file, S_threshold, S_action, S_closebra, S_unknown);
	}
    }
}

#define HAVE_mavis_drop_in
static void mavis_drop_in(mavis_ctx *mcx)
{
    if (mcx->path)
	free(mcx->path);
}

static int set_error_count(mavis_ctx *mcx, int add)
{
    int count = 0;
    if (mcx->path) {
	int fn = open(mcx->path, O_RDWR | O_CREAT | O_NOFOLLOW, 0644);
	struct flock flock = {.l_type = F_WRLCK,.l_whence = SEEK_SET };
	fcntl(fn, F_SETLK, &flock);
	if (add) {
	    read(fn, &count, sizeof(count));
	    count++;
	}
	lseek(fn, 0, SEEK_SET);
	write(fn, &count, sizeof(count));
	close(fn);
    }
    return count;
}

#define HAVE_mavis_recv_out
static int mavis_recv_out(mavis_ctx *mcx, av_ctx **ac)
{
    if (!mcx->path)
	return MAVIS_FINAL;

    char *r = av_get(*ac, AV_A_RESULT);
    if (!r)
	return MAVIS_FINAL;

    if (!strcmp(r, AV_V_RESULT_ERROR)) {
	int error_count = set_error_count(mcx, 1);
	if (error_count < mcx->threshold)
	    av_set(*ac, AV_A_RESULT, AV_V_RESULT_FAIL);
    } else if (!strcmp(r, AV_V_RESULT_OK) || !strcmp(r, AV_V_RESULT_FAIL)) {
	set_error_count(mcx, 0);
    }
    return MAVIS_FINAL;
}

#include "mavis_glue.c"
