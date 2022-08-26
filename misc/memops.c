/*
 * memops.c
 * (C) 2000-2011 Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include "misc/memops.h"
#include "mavis/log.h"

char *XXstrdup(const char *s, char *file, int line)
{
    char *a = strdup(s);
    if (!a) {
	logerr("strdup (%s:%d)", file, line);
	exit(EX_OSERR);
    }
    return a;
}

void *XXcalloc(size_t nmemb, size_t size, char *file, int line)
{
    void *a = calloc(nmemb, size);
    if (!a) {
	logerr("calloc (%s:%d)", file, line);
	exit(EX_OSERR);
    }
    return a;
}

void *XXrealloc(void *ptr, size_t size, char *file, int line)
{
    void *a = realloc(ptr, size);
    if (!a) {
	logerr("realloc (%s:%d)", file, line);
	exit(EX_OSERR);
    }
    return a;
}
