/*
 * setproctitle.c
 * (C) 1999-2011 Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * setproctitle() routines, should work for MacOS and Linux.
 *
 * $Id$
 *
 */

#include "misc/sysconf.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include "misc/strops.h"
#include "misc/setproctitle.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

#ifdef WANT_SETPROCTITLE
static char *proctitle;
static size_t proctitle_len;

void setproctitle_init(char **argv, char **envv)
{
    char **a = argv, *end, *progname;
    int len;

    proctitle = *argv;
    progname = strdup(basename(*argv));
    end = proctitle - 1;

    for (a = argv; *a == end + 1; a++)
	do
	    end++;
	while (*end);

    if (envv)
	for (a = envv; *a == end + 1; a++) {
	    do
		end++;
	    while (*end);
	    *a = strdup(*a);
	}

    proctitle_len = end - proctitle + 1;

    for (; *argv; *argv++ = NULL);
    len = snprintf(proctitle, proctitle_len, "%s: ", progname);
    if (len < (int) proctitle_len)
	proctitle += len, proctitle_len -= len;
}

void setproctitle(const char *format, ...)
{
    size_t len;
    va_list ap;

    va_start(ap, format);
    len = vsnprintf(proctitle, proctitle_len, format, ap);
    va_end(ap);
    if (len < proctitle_len)
	memset(proctitle + len, 0, proctitle_len - len);
}
#else
void setproctitle_init(char **argv __attribute__((unused)), char **envv __attribute__((unused)))
{
}

#ifndef HAVE_SETPROCTITLE
void setproctitle(const char *format __attribute__((unused)), ...)
{
}
#endif				/* HAVE_SETPROCTITLE */
#endif				/* __linux__ */
