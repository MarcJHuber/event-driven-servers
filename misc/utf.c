/*
 * utf.c
 * portions (C) 1999 Marc Huber <Marc.Huber@web.de>
 *
 * Most of this code was originally taken from
 * draft-ietf-ftpext-intl-ftp-06.txt, which later evolved to RFC 2640.
 * (C) 1999 B. Curtin (curtinw@ftm.disa.mil).
 *
 * $Id$
 *
 */

/*
 * Full Copyright Statement of RFC2640:
 *
 * Copyright (C) The Internet Society (1999).  All Rights Reserved.
 *
 * This document and translations of it may be copied and furnished to
 * others, and derivative works that comment on or otherwise explain it
 * or assist in its implementation may be prepared, copied, published
 * and distributed, in whole or in part, without restriction of any
 * kind, provided that the above copyright notice and this paragraph are
 * included on all such copies and derivative works.  However, this
 * document itself may not be modified in any way, such as by removing
 * the copyright notice or references to the Internet Society or other
 * Internet organizations, except as needed for the purpose of
 * developing Internet standards in which case the procedures for
 * copyrights defined in the Internet Standards process must be
 * followed, or as required to translate it into languages other than
 * English.
 *
 * The limited permissions granted above are perpetual and will not be
 * revoked by the Internet Society or its successors or assigns.
 *
 * This document and the information contained herein is provided on an
 * "AS IS" basis and THE INTERNET SOCIETY AND THE INTERNET ENGINEERING
 * TASK FORCE DISCLAIMS ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING
 * BUT NOT LIMITED TO ANY WARRANTY THAT THE USE OF THE INFORMATION
 * HEREIN WILL NOT INFRINGE ANY RIGHTS OR ANY IMPLIED WARRANTIES OF
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

#ifndef __GNUC__
#define __attribute__(A)
#endif				/* __GNUC__ */

static const char rcsid[] __attribute__((used)) = "$Id$";

#include "misc/utf.h"

u_int local_to_utf8(char *local_buf, u_int local_len, u_char * utf8_buf)
{
    const char *local_endbuf = local_buf + local_len;
    u_int utf8_len = 0;		/* return value for UTF8 size */

    u_char *t_utf8_buf = utf8_buf;	/* Temporary pointer to load UTF8 values */

    for (; local_buf < local_endbuf; local_buf++) {
	if (!(*local_buf & 0x80)) {	/* ASCII chars, no conversion needed */
	    *t_utf8_buf++ = (u_char) * local_buf;
	    utf8_len++;
	    continue;
	} else
	    /* In the 2 byte utf-8 range */
	{
	    *t_utf8_buf++ = (u_char) (0xC0 | (*local_buf >> 6));
	    *t_utf8_buf++ = (u_char) (0x80 | (*local_buf & 0x3F));
	    utf8_len += 2;
	    continue;
	}
    }
    return (utf8_len);
}

int utf8_to_local(char *local_buf, u_int utf8_len, u_char * utf8_buf)
{
    const u_char *utf8_endbuf = utf8_buf + utf8_len;
    u_int local_len = 0;

    for (; utf8_buf < utf8_endbuf; local_len++) {
	if ((*utf8_buf & 0x80) == 0x00) {	/* ASCII chars, no conversion needed */
	    *local_buf++ = (char) (0xff & ((u_int) (*utf8_buf)));
	    utf8_buf++;
	    continue;
	}
	if ((*utf8_buf & 0xE0) == 0xC0) {	/* In the 2 byte utf-8 range */
	    *local_buf++ = (char)
		(0xff & (((u_int) (*(utf8_buf) & 0x3F) << 6) | ((u_int) (*(utf8_buf + 1) & 0x7F))));
	    utf8_buf += 2;
	    continue;
	}
	if ((*utf8_buf & 0xF0) == 0xE0) {	/* In the 3 byte utf-8 range */
	    *local_buf++ = (char)
		(0xff & (((u_int) (*(utf8_buf) & 0x1F) << 12) | ((u_int) (*(utf8_buf + 1) & 0x7F) << 6) | ((u_int) (*(utf8_buf + 2) & 0x7F))));
	    utf8_buf += 3;
	    continue;
	}
	if ((*utf8_buf & 0xF8) == 0xF0) {	/* In the 4 byte utf-8 range */
	    *local_buf++ = (char)
		(0xff & (((u_int) (*(utf8_buf) & 0x0F) << 18) |
			 ((u_int) (*(utf8_buf + 1) & 0x7F) << 12) | ((u_int) (*(utf8_buf + 2) & 0x7F) << 6) | ((u_int) (*(utf8_buf + 3) & 0x7F))));
	    utf8_buf += 4;
	    continue;
	}
	if ((*utf8_buf & 0xFC) == 0xF8) {	/* In the 5 byte utf-8 range */
	    *local_buf++ = (char)
		(0xff & (((u_int) (*(utf8_buf) & 0x7) << 24) |
			 ((u_int) (*(utf8_buf + 1) & 0x7F) << 18) |
			 ((u_int) (*(utf8_buf + 2) & 0x7F) << 12) | ((u_int) (*(utf8_buf + 3) & 0x7F) << 6) | ((u_int) (*(utf8_buf + 4) & 0x7F))));
	    utf8_buf += 5;
	    continue;
	}
	if ((*utf8_buf & 0xFE) == 0xFC) {	/* In the 6 byte utf-8 range */
	    *local_buf++ = (char)
		(0xff & (((u_int) (*(utf8_buf) & 0x3) << 30) |
			 ((u_int) (*(utf8_buf + 1) & 0x7F) << 24) |
			 ((u_int) (*(utf8_buf + 2) & 0x7F) << 18) |
			 ((u_int) (*(utf8_buf + 3) & 0x7F) << 12) | ((u_int) (*(utf8_buf + 4) & 0x7F) << 6) | ((u_int) (*(utf8_buf + 5) & 0x7F))));
	    utf8_buf += 6;
	    continue;
	}
    }
    return (local_len);
}

int utf8_valid(const u_char * buf, u_int len)
{
    const u_char *endbuf = buf + len;
    u_char byte2mask = 0x00, c;
    int trailing = 0;		/* trailing (continuation) bytes to follow */

    while (buf != endbuf) {
	c = *buf++;
	if (trailing) {
	    if ((c & 0xC0) == 0x80) {	/* Does trailing byte follow UTF-8 format? */
		if (byte2mask) {	/* Need to check 2nd byte for proper range? */
		    if (c & byte2mask)	/* Are appropriate bits set? */
			byte2mask = 0x00;
		    else
			return 0;
		}
		trailing--;
		continue;
	    }
	    return 0;
	}
	if ((c & 0x80) == 0x00)	/* valid 1 byte UTF-8 */
	    continue;
	if ((c & 0xE0) == 0xC0) {	/* valid 2 byte UTF-8 */
	    if (c & 0x1E) {	/* Is UTF-8 byte in proper range? */
		trailing = 1;
		continue;
	    }
	    return 0;
	}
	if ((c & 0xF0) == 0xE0) {	/* valid 3 byte UTF-8 */
	    if (!(c & 0x0F))	/* Is UTF-8 byte in proper range? */
		byte2mask = 0x20;	/* If not set mask to check next byte */
	    trailing = 2;
	    continue;
	}
	if ((c & 0xF8) == 0xF0) {	/* valid 4 byte UTF-8 */
	    if (!(c & 0x07))	/* Is UTF-8 byte in proper range? */
		byte2mask = 0x30;	/* If not set mask to check next byte */
	    trailing = 3;
	    continue;
	}
	if ((c & 0xFC) == 0xF8) {	/* valid 5 byte UTF-8 */
	    if (!(c & 0x03))	/* Is UTF-8 byte in proper range? */
		byte2mask = 0x38;	/* If not set mask to check next byte */
	    trailing = 4;
	    continue;
	}
	if ((c & 0xFE) == 0xFC) {	/* valid 6 byte UTF-8 */
	    if (!(c & 0x01))	/* Is UTF-8 byte in proper range? */
		byte2mask = 0x3C;	/* If not set mask to check next byte */
	    trailing = 5;
	    continue;
	}
	return 0;
    }
    return trailing == 0;
}

u_int ucs4_to_utf8(u_int * ucs4_buf, u_int ucs4_len, u_char * utf8_buf)
{
    const u_int *ucs4_endbuf = ucs4_buf + ucs4_len;
    u_int utf8_len = 0;		/* return value for UTF8 size */

    u_char *t_utf8_buf = utf8_buf;	/* Temporary pointer to load UTF8 values */

    for (; ucs4_buf < ucs4_endbuf; ucs4_buf++) {
	if (!(*ucs4_buf & 0xffffff80)) {	/* ASCII chars, no conversion needed */
	    *t_utf8_buf++ = (u_char) * ucs4_buf;
	    utf8_len++;
	    continue;
	}
	if (!(*ucs4_buf & 0xfffff800)) {	/* In the 2 byte utf-8 range */
	    *t_utf8_buf++ = (u_char) (0xC0 | (*ucs4_buf >> 6));
	    *t_utf8_buf++ = (u_char) (0x80 | (*ucs4_buf & 0x3F));
	    utf8_len += 2;
	    continue;
	}
	if (!(*ucs4_buf & 0xFFFF0000)) {	/* In the 3 byte utf-8 range */
	    *t_utf8_buf++ = (u_char) (0xE0 | ((*ucs4_buf >> 12)));
	    *t_utf8_buf++ = (u_char) (0x80 | ((*ucs4_buf >> 6) & 0x3F));
	    *t_utf8_buf++ = (u_char) (0x80 | ((*ucs4_buf) & 0x3F));
	    utf8_len += 3;
	    continue;
	}
	if (!(*ucs4_buf & 0xffe00000)) {	/* In the 4 byte utf-8 range */
	    *t_utf8_buf++ = (u_char) (0xF0 | ((*ucs4_buf >> 18)));
	    *t_utf8_buf++ = (u_char) (0x80 | ((*ucs4_buf >> 16) & 0x3F));
	    *t_utf8_buf++ = (u_char) (0x80 | ((*ucs4_buf >> 6) & 0x3F));
	    *t_utf8_buf++ = (u_char) (0x80 | ((*ucs4_buf) & 0x3F));
	    utf8_len += 4;
	    continue;
	}
	if (!(*ucs4_buf & 0xfc000000)) {	/* In the 5 byte utf-8 range */
	    *t_utf8_buf++ = (u_char) (0xF8 | ((*ucs4_buf >> 24)));
	    *t_utf8_buf++ = (u_char) (0x80 | ((*ucs4_buf >> 18) & 0x3f));
	    *t_utf8_buf++ = (u_char) (0x80 | ((*ucs4_buf >> 12) & 0x3f));
	    *t_utf8_buf++ = (u_char) (0x80 | ((*ucs4_buf >> 6) & 0x3f));
	    *t_utf8_buf++ = (u_char) (0x80 | ((*ucs4_buf) & 0x3f));
	    utf8_len += 5;
	    continue;
	}
	if (!(*ucs4_buf & 0x80000000)) {	/* In the 6 byte utf-8 range */
	    *t_utf8_buf++ = (u_char) (0xF8 | ((*ucs4_buf >> 30)));
	    *t_utf8_buf++ = (u_char) (0x80 | ((*ucs4_buf >> 24) & 0x3f));
	    *t_utf8_buf++ = (u_char) (0x80 | ((*ucs4_buf >> 18) & 0x3f));
	    *t_utf8_buf++ = (u_char) (0x80 | ((*ucs4_buf >> 12) & 0x3f));
	    *t_utf8_buf++ = (u_char) (0x80 | ((*ucs4_buf >> 6) & 0x3f));
	    *t_utf8_buf++ = (u_char) (0x80 | ((*ucs4_buf) & 0x3f));
	    utf8_len += 6;
	    continue;
	}
    }
    return (utf8_len);
}

int utf8_to_ucs4(u_int * ucs4_buf, u_int utf8_len, u_char * utf8_buf)
{
    const u_char *utf8_endbuf = utf8_buf + utf8_len;
    u_int ucs_len = 0;

    for (; utf8_buf < utf8_endbuf; ucs_len++) {
	if ((*utf8_buf & 0x80) == 0x00) {	/* ASCII chars, no conversion needed */
	    *ucs4_buf++ = (u_int) (*utf8_buf);
	    utf8_buf++;
	    continue;
	}
	if ((*utf8_buf & 0xE0) == 0xC0) {	/* In the 2 byte utf-8 range */
	    *ucs4_buf++ = ((u_int) (*(utf8_buf) & 0x3F) << 6) | ((u_int) (*(utf8_buf + 1) & 0x7F));
	    utf8_buf += 2;
	    continue;
	}
	if ((*utf8_buf & 0xF0) == 0xE0) {	/* In the 3 byte utf-8 range */
	    *ucs4_buf++ = ((u_int) (*(utf8_buf) & 0x1F) << 12) | ((u_int) (*(utf8_buf + 1) & 0x7F) << 6) | ((u_int) (*(utf8_buf + 2) & 0x7F));
	    utf8_buf += 3;
	    continue;
	}
	if ((*utf8_buf & 0xF8) == 0xF0) {	/* In the 4 byte utf-8 range */
	    *ucs4_buf++ =
		((u_int) (*(utf8_buf) & 0x0F) << 18) |
		((u_int) (*(utf8_buf + 1) & 0x7F) << 12) | ((u_int) (*(utf8_buf + 2) & 0x7F) << 6) | ((u_int) (*(utf8_buf + 3) & 0x7F));
	    utf8_buf += 4;
	    continue;
	}
	if ((*utf8_buf & 0xFC) == 0xF8) {	/* In the 5 byte utf-8 range */
	    *ucs4_buf++ =
		((u_int) (*(utf8_buf) & 0x7) << 24) |
		((u_int) (*(utf8_buf + 1) & 0x7F) << 18) |
		((u_int) (*(utf8_buf + 2) & 0x7F) << 12) | ((u_int) (*(utf8_buf + 3) & 0x7F) << 6) | ((u_int) (*(utf8_buf + 4) & 0x7F));
	    utf8_buf += 5;
	    continue;
	}
	if ((*utf8_buf & 0xFE) == 0xFC) {	/* In the 6 byte utf-8 range */
	    *ucs4_buf++ =
		((u_int) (*(utf8_buf) & 0x3) << 30) |
		((u_int) (*(utf8_buf + 1) & 0x7F) << 24) |
		((u_int) (*(utf8_buf + 2) & 0x7F) << 18) |
		((u_int) (*(utf8_buf + 3) & 0x7F) << 12) | ((u_int) (*(utf8_buf + 4) & 0x7F) << 6) | ((u_int) (*(utf8_buf + 5) & 0x7F));
	    utf8_buf += 6;
	    continue;
	}
    }
    return (ucs_len);
}
