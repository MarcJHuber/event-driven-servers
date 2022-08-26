/*
 * tohex.c
 * (C) 2000-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#ifndef __GNUC__
#define __attribute__(A)
#endif				/* __GNUC__ */

static const char rcsid[] __attribute__((used)) = "$Id$";

#include "misc/tohex.h"

char *tohex(u_char * in, int len, char *out)
{
    char *d, hexmap[] = "0123456789abcdef";
    int i;

    for (d = out, i = 0; i < len; i++) {
	*d++ = hexmap[in[i] >> 4];
	*d++ = hexmap[in[i] & 0xf];
    }

    *d = 0;

    return out;
}
