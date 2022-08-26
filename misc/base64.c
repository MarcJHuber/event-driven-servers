/* base64.c
 * (C) 1999 Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include <sys/types.h>
#include "misc/base64.h"

#ifndef __GNUC__
#define __attribute__(A)
#endif				/* __GNUC__ */

static const char rcsid[] __attribute__((used)) = "$Id$";

static u_char *base64_table = (u_char *)
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int base64enc(char *inbuf, size_t inbuf_len, char *outbuf, size_t *outbuf_len)
{
    u_int a;
    char *outbuf_start = outbuf;
    size_t required_outlen = (inbuf_len * 8 + 5) / 6;

    if (*outbuf_len < required_outlen + 1)
	return -1;

    while (inbuf_len > 2) {
	a = ((inbuf[0] & 0xff) << 16) | ((inbuf[1] & 0xff) << 8) | ((inbuf[2] & 0xff));
	inbuf += 3, inbuf_len -= 3;
	*outbuf++ = base64_table[(a >> 18) & 0x3f];
	*outbuf++ = base64_table[(a >> 12) & 0x3f];
	*outbuf++ = base64_table[(a >> 6) & 0x3f];
	*outbuf++ = base64_table[(a) & 0x3f];
    }

    if (inbuf_len) {
	a = (inbuf[0] & 0xff) << 16;

	if (inbuf_len == 2)
	    a |= (inbuf[1] & 0xff) << 8;

	*outbuf++ = base64_table[(a >> 18) & 0x3f];
	*outbuf++ = base64_table[(a >> 12) & 0x3f];

	if (inbuf_len == 2) {
	    *outbuf++ = base64_table[(a >> 6) & 0x3f];
	    *outbuf++ = '=';
	}
	*outbuf++ = '=';
    }
    *outbuf = 0;

    *outbuf_len = (int) (outbuf - outbuf_start);
    return 0;

}

static u_char base64_reverse[256];

int base64dec(char *inbuf, size_t inbuf_len, char *outbuf, size_t *outbuf_len)
{
    static int initialized = 0;
    char *outbuf_start = outbuf;
    size_t i;
    u_char c;

    if (!initialized) {
	initialized++;
	for (i = 0; i < 256; i++)
	    base64_reverse[i] = 255;
	for (i = 0; i < 64; i++)
	    base64_reverse[base64_table[i]] = i;
    }

    if (*outbuf_len < 3 * (inbuf_len >> 2) + 1)
	return -1;

    for (i = 0; i < inbuf_len && *inbuf != '='; i++)
	if ((c = base64_reverse[(int) *inbuf++]) != 255)
	    switch (i & 3) {
	    case 0:
		*outbuf = c << 2;
		break;
	    case 1:
		*outbuf++ |= c >> 4;
		*outbuf = c << 4;
		break;
	    case 2:
		*outbuf++ |= c >> 2;
		*outbuf = c << 6;
		break;
	    case 3:
		*outbuf++ |= c;
		break;
	    }

    if (i & 3)
	outbuf++;

    *outbuf = 0;

    *outbuf_len = (int) (outbuf - outbuf_start);
    return 0;
}
