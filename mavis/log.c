/*
 * log.c
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 *
 * $Id$
 *
 */

#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include "log.h"
#include "mavis.h"
#include "misc/memops.h"
#include "misc/strops.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

static int logopened = 0;

extern struct common_data common_data;

void logopen(void)
{
    char *ident = common_data.syslog_ident;
    if (!ident)
	ident = common_data.progname;
    if (!ident)
	ident = "";
    if (logopened)
	closelog();
    logopened = -1;
    openlog(ident, LOG_NDELAY | LOG_PID, common_data.syslog_facility);
}

void logmsg(char *format, ...)
{
    va_list ap;
    size_t len = 1024, nlen;
    char *tmpbuf = alloca(len);

    va_start(ap, format);
    nlen = vsnprintf(tmpbuf, len, format, ap);
    va_end(ap);
    if (len <= nlen) {
	tmpbuf = alloca(++nlen);
	va_start(ap, format);
	vsnprintf(tmpbuf, nlen, format, ap);
	va_end(ap);
    }
    syslog(common_data.syslog_level | common_data.syslog_facility, "%s", tmpbuf);
}

void logerr(char *format, ...)
{
    int e = errno;
    va_list ap;
    size_t len = 1024, nlen;
    char *tmpbuf = alloca(len);

    va_start(ap, format);
    nlen = vsnprintf(tmpbuf, len, format, ap);
    if (len <= nlen) {
	tmpbuf = alloca(++nlen);
	vsnprintf(tmpbuf, nlen, format, ap);
    }
    va_end(ap);
    syslog(common_data.syslog_level | common_data.syslog_facility, "%s: %s", tmpbuf, strerror(e));
    errno = e;
}
