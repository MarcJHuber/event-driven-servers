/*
 * ostype.c
 * (C) 2001 Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include <sys/types.h>
#include "misc/sysconf.h"
#include "misc/ostype.h"
#include "misc/memops.h"
#include <stdio.h>
#include <ctype.h>
#include <sys/utsname.h>

static const char rcsid[] __attribute__((used)) = "$Id$";

static char *os = NULL;

char *ostype()
{
    if (!os) {
	char b[1024], *t;
	struct utsname buf;
	uname(&buf);
	snprintf(b, sizeof(b), "%s-%s-%s", buf.sysname, buf.release, buf.machine);
	for (t = b; *t; t++)
	    *t = tolower((int) *t);
	os = Xstrdup(b);
    }
    return os;
}

char *ostypef(char *format, char *s, size_t len)
{
    char *t = s;
    size_t l;

    len--;
    for (; *format && len; format++)
	if (*format == '%')
	    switch (*++format) {
	    case 'o':
		l = snprintf(t, len, "%s", ostype());
		if (l < len)
		    t += l, len -= l;
		break;
	    case 'O':
		l = snprintf(t, len, "%s", OS);
		if (l < len)
		    t += l, len -= l;
		break;
	    case '%':
		if (1 < len)
		    *t++ = '%', len--;
		break;
	} else
	    *t++ = *format, len--;
    *t = 0;
    return s;
}
