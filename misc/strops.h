/*
 * strops.h
 * (C)1997-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id: strops.h,v 1.7 2011/07/17 19:12:19 marc Exp $
 *
 */

#ifndef __STROPS_H__
#define __STROPS_H__

#include "misc/sysconf.h"

#include <sys/types.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include "misc/memops.h"

#ifdef WITH_BASENAME_LIBGEN
#include <libgen.h>
#endif

static __inline__ void chomp(char *b)
{
    if (!b)
	return;

    while (*b && *b != '\r' && *b != '\n')
	b++;

    *b = 0;
}

static __inline__ char *crop(char *b)
{
    char *a;

    if (!b)
	return NULL;

    for (; *b && isspace((int) *b); b++);
    for (a = b; *a; a++);
    for (--a; a > b && isspace((int) *a); *a-- = 0);
    return b;
}

static __inline__ char *lower(char *s)
{
    char *b = s;
    for (; *b; b++)
	*b = tolower((int) *b);
    return s;
}

static __inline__ char *strset(char **s, char *v)
{
    if (v) {
	if (*s)
	    free(*s);
	*s = Xstrdup(v);
    }
    return *s;
}

#ifndef WITH_BASENAME
static __inline__ char *basename(const char *path)
{
    char *a = (char *) path, *b = (char *) path;
    if (!path || !*path)
	return ".";

    for (; *a; a++)
	if (*a == '/')
	    b = a + 1;
    return *b ? b : ".";
}
#endif				/* WITH_BASENAME */

#endif				/* __STROPS_H__ */
