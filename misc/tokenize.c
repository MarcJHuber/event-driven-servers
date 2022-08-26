/*
 * tokenize.c (C) 2000-2011 Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include <sys/types.h>
#include <string.h>
#include <ctype.h>

static char *get_token(char *string, char **remainder)
{
    int quoted = 0;
    char *start = NULL;
    *remainder = NULL;
    if (string) {
	while (*string && isspace((int) *string))
	    string++;
	while (*string) {
	    switch (*string) {
	    case '\t':
	    case ' ':
		if (quoted)
		    break;
	    case '"':
		if (start) {
		    *string++ = 0;
		    *remainder = string;
		    return start;
		} else
		    start = string + 1, quoted = -1;
		break;
	    case '\\':
		if (!quoted)
		    memmove(string, string + 1, strlen(string + 1));
		break;
	    default:
		if (!start)
		    start = string;
	    }
	    if (*string)
		string++;
	}
    }
    return start;
}

int tokenize(char *string, char **vector, int v_len)
{
    char *token, *remainder = string;
    int vector_len = 0;

    v_len--;

    do
	vector[vector_len++] = token = get_token(remainder, &remainder);
    while (token && vector_len < v_len);

    if (token)
	return -1;

    if (vector_len > 0 && !vector[vector_len - 1])
	vector_len--;
    else
	vector[vector_len] = NULL;

    return vector_len;
}
