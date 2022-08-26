/*
 * glob.c
 * (C) 2000-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "misc/sysconf.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "misc/memops.h"
#include "glob.h"

struct glob_pattern {
    u_int set[8];
    u_int repeat:1;
    u_int valid:1;
};

#define is_set(A)	\
	(pattern->set[(u_int) A >> 5] & (1 << ((u_int) A & 0x1F)))
#define do_clear(A)	\
	pattern[i].set[(u_int) A >> 5] &= ~(1 << ((u_int) A & 0x1F))
#define do_set(A)	\
	pattern[i].set[(u_int) A >> 5] |= (1 << ((u_int) A & 0x1F))

int glob_exec(struct glob_pattern *pattern, char *string)
{
    if (!string || !pattern)
	return 0;

    while (1) {
	if (!pattern->valid)
	    return !*string;

	if (!is_set(*string))
	    return 0;

	if (pattern->repeat && ((*string && glob_exec(pattern, string + 1)) || glob_exec(pattern + 1, string)))
	    return -1;

	if (!*string)
	    return 0;

	pattern++, string++;
    }
}

void glob_free(struct glob_pattern *pattern)
{
    if (pattern)
	free(pattern);
}

struct glob_pattern *glob_comp(char *string)
{
    struct glob_pattern *pattern;
    int i = 0, negate = 0, in_range = 0;
    char lastchar = 0;
    int expand_count = 0;

    if (!string)
	return NULL;

    pattern = Xcalloc(strlen(string) + 1, sizeof(struct glob_pattern));
    while (*string) {
	switch (*string) {
	case '*':
	    if ((i > 0) && (pattern[i - 1].repeat == 1) &&
		(pattern[i - 1].set[0] == 0xffffffff) &&
		(pattern[i - 1].set[1] == 0xffffffff) &&
		(pattern[i - 1].set[2] == 0xffffffff) &&
		(pattern[i - 1].set[3] == 0xffffffff) &&
		(pattern[i - 1].set[4] == 0xffffffff) &&
		(pattern[i - 1].set[5] == 0xffffffff) && (pattern[i - 1].set[6] == 0xffffffff) && (pattern[i - 1].set[7] == 0xffffffff)) {
		string++;
		continue;
	    }
	    pattern[i].repeat = 1;
	case '?':
	    pattern[i].set[0] = pattern[i].set[1] = pattern[i].set[2] =
		pattern[i].set[3] = pattern[i].set[4] = pattern[i].set[5] = pattern[i].set[6] = pattern[i].set[7] = 0xffffffff;
	    expand_count++;
	    break;
	case '[':
	    negate = 0;
	    if (*++string == '!') {
		negate = 1;
		pattern[i].set[0] = pattern[i].set[1] = pattern[i].set[2] =
		    pattern[i].set[3] = pattern[i].set[4] = pattern[i].set[5] = pattern[i].set[6] = pattern[i].set[7] = 0xffffffff;
		string++;
	    }
	    if (*string == ']' || *string == '-') {
		if (negate)
		    do_clear(*string);
		else
		    do_set(*string);
		string++;
	    }

	    while (*string && *string != ']') {
		switch ((u_int) * string) {
		case '-':
		    in_range = 1;
		    break;
		default:
		    if (in_range) {
			int j;
			if (negate)
			    for (j = lastchar; j <= *string; j++)
				do_clear(j);
			else
			    for (j = lastchar; j <= *string; j++)
				do_set(j);
			in_range = 0;
		    } else {
			if (negate)
			    do_clear(*string);
			else
			    do_set(*string);
		    }
		    lastchar = *string;
		}
		string++;
	    }

	    if (in_range) {
		in_range = 0;
		if (negate)
		    do_clear('-');
		else
		    do_set('-');
	    }
	    negate = 0;
	    expand_count++;
	    break;
	default:
	    do_set(*string);
	}
	pattern[i++].valid = 1;
	if (*string)
	    string++;
	if (expand_count > 12) {
	    free(pattern);
	    return NULL;
	}
    }

    return pattern;
}
