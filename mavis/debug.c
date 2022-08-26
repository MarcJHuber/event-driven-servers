/*
 * debug.c
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 *
 * $Id$
 *
 */

#ifndef __GNUC__
#define __attribute__(A)
#endif				/* __GNUC__ */

static const char debugrcsid[] __attribute__((used)) = "$Id$";

#define _DEBUG_MAIN_
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>

#include "debug.h"
#include "misc/memops.h"
#include "mavis.h"

void debug_setpid()
{
    common_data.pid = getpid();
}

void debug(u_long level, char *format, ...)
{
    if (level & common_data.debug) {
	static int indent = 0;
	va_list ap;
	int olderrno;
	size_t len = 1024, nlen;
	char *tmpbuf = alloca(len);
	char *t;
	char spaces[] = "                                        " "                                        " "                                        ";

	olderrno = errno;

	va_start(ap, format);
	nlen = vsnprintf(tmpbuf, len, format, ap);
	va_end(ap);
	if (nlen >= len) {
	    tmpbuf = alloca(++nlen);
	    va_start(ap, format);
	    vsnprintf(tmpbuf, nlen, format, ap);
	    va_end(ap);
	}

	if (tmpbuf[0] == '-' && indent > 0)
	    indent--;

	for (t = tmpbuf; t[0] && t[1]; t++)
	    if (iscntrl((int) *t))
		*t = '^';

	fprintf(stderr, "%6ld: %.*s%s", (long) common_data.pid, indent, spaces, tmpbuf);

	if (tmpbuf[0] == '+' && indent < (int) sizeof(spaces) - 2)
	    indent++;

	fflush(stderr);
	errno = olderrno;
    }
}
