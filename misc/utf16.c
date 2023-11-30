/*
 * utf16.c
 * (C) 2023 Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include <string.h>
#include <stdlib.h>
#include "misc/sysconf.h"
#include "misc/utf.h"

static int is_valid_utf8(char *in, size_t len)
{
    u_char *u = (u_char *) in;

    int cont = 0;
    for (; *u && len; len--) {
	if (*u & 0x80) {
	    if ((*u & 0x80) == 0x00) {
		cont = 0;
	    } else if ((*u & 0xE0) == 0xC0) {
		cont = 1;
	    } else if ((*u & 0xF0) == 0xE0) {
		cont = 2;
	    } else if ((*u & 0xF8) == 0xF0) {
		cont = 3;
	    } else
		return 0;
	    u++;
	    for (; cont; cont--, u++)
		if ((*u & 0xC0) != 0x80)
		    return 0;
	}
    }
    return -1;
}

/*

UTF-8                                 UT-16LE

0abcdefg                              0abcdefg 00000000
110abcde 10fghijk                     defghijk 00000abc
1110abcd 10efghij 10klmnop            ijklmnop abcdefgh
11110abc 10defghi 10jklmno 10pqrstu   nopqrstu 110110lm defghijk 110111bc
*/

int utf8_to_utf16le(char *in, size_t inlen, char **out, size_t *outlen)
{
    if (!is_valid_utf8(in, inlen))
	return -1;

    u_char *a = alloca(2 * inlen + 1);
    memset(a, 0, 2 * inlen + 1);
    u_char *o = a;
    u_char *u = (u_char *) in;

    while (*u) {
	if ((*u & 0x80) == 0x00) {
	    *o++ = *u;
	    o++;
	    u++;
	} else if ((*u & 0xE0) == 0xC0) {
	    *o++ = (*u << 6) | (*(u + 1) & 0x3F);	// de fghijk
	    *o++ = (*u & 0x1E) >> 2;	// abc
	    u++;
	    u++;
	} else if ((*u & 0xF0) == 0xE0) {
	    *o++ = ((*(u + 1) & 0x03) << 6) | (*(u + 2) & 0x3F);	// ij klmnop
	    *o++ = (*u << 4) | ((*(u + 1) & 0x3F) >> 2);	// abcd efgh
	    u++;
	    u++;
	    u++;
	} else if ((*u & 0xF8) == 0xF0) {
	    *o++ = (*(u + 2) << 6) | (*(u + 3) & 0x3F);	//no pqrstu
	    *o++ = 0xD8 | ((*(u + 2) & 0x0C) >> 2);	// 110110 lm
	    *o++ = ((*(u + 1) & 0x3F) << 2) | ((*(u + 3) & 0x3F) >> 4);	// defghi jk
	    *o++ = 0xDC | (*u & 0x03);	// 110111 bc
	    u++;
	    u++;
	    u++;
	    u++;
	}
    }
    *outlen = o - a;
    *out = calloc(1, *outlen + 2);
    memcpy(*out, a, *outlen);

    return 0;
}
