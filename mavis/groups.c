/*
 * groups.c
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 *
 * $Id$
 *
 */

#include "misc/sysconf.h"
#include <stdio.h>
#include <string.h>
#include <grp.h>
#include <sys/types.h>
#include <limits.h>
#include <unistd.h>
#include "debug.h"
#include "groups.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

#ifndef NGROUPS
#define NGROUPS 100
#endif

char *groups_list2ascii(size_t size, gid_t * list, char *buf, size_t buflen)
{
    u_int i;
    char *t = buf;

    DebugIn(DEBUG_PROC);

    if (size > NGROUPS_MAX)
	size = NGROUPS_MAX;

    for (i = 0; i < size; i++) {
	int len;
	if (i)
	    *t++ = ',';
	len = snprintf(t, (size_t) (buf + buflen - t), "%lu", (u_long) list[i]);
	if (len < buf + buflen - t)
	    t += len;
    }
    DebugOut(DEBUG_PROC);
    return buf;
}

void groups_ascii2list(char *alist, int *size, gid_t * list)
{
    char *t;
    char *next = alist;
    u_long g;
    int i = 0;

    DebugIn(DEBUG_PROC);

    while (next && i < NGROUPS_MAX) {
	t = strchr(alist, ',');
	if (t) {
	    *t = 0;
	    next = t + 1;
	} else
	    next = NULL;

	if (1 == sscanf(alist, "%lu", &g))
	    list[i++] = (gid_t) g;

	alist = next;
    }

    *size = i;
    DebugOut(DEBUG_PROC);
}

/*
 * Retrieving the group access list is rather inefficient, but we don't
 * really care, because we'll be using the caching module.
 */

char *groups_getlist(char *name, gid_t gid, char *buf, size_t buflen)
{
#ifdef HAVE_GETGROUPLIST
    GETGROUPLIST_ARG2_TYPE g[NGROUPS];
    int n = NGROUPS;
    int i;
    size_t l = 0;
    char *b = buf;

    DebugIn(DEBUG_MAVIS);

    getgrouplist(name, (GETGROUPLIST_ARG2_TYPE) gid, g, &n);

    for (i = 0; i < n; i++) {
	int j;
	if (buflen < l + 20)
	    return buf;
	if (i)
	    *b++ = ',', l++;
	j = snprintf(b, (size_t) (b + buflen - b), "%d", g[i]);
	l += j;
	if (l >= buflen)
	    break;
	b += j;
    }

    DebugOut(DEBUG_MAVIS);
    return buf;
#else
    struct group *g;
    char *t = buf, **m;
    size_t len;

    DebugIn(DEBUG_MAVIS);

    len = snprintf(buf, buflen, "%lu", (u_long) gid);

    if (len < buflen) {
	t += len;

	setgrent();
	while ((g = getgrent()))
	    if ((m = g->gr_mem)) {
		while (*m && strcmp(*m, name))
		    m++;
		if (*m) {
		    if (buf + buflen - t > 2) {
			*t++ = ',';
			*t = 0;
		    }
		    len = snprintf(t, (size_t) (buf + buflen - t), "%lu", (u_long) g->gr_gid);
		    if (len >= (size_t) (buf + buflen - t))
			break;
		    t += len;
		}
	    }
	endgrent();
    }
    DebugOut(DEBUG_MAVIS);
    return buf;
#endif
}
