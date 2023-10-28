/* utf.h
 * (C) 1999 Marc Huber <Marc.Huber@web.de>
 *
 * $Id: utf.h,v 1.3 2005/12/31 12:14:23 huber Exp $
 *
 */

#include <sys/types.h>

u_int local_to_utf8(char *, u_int, u_char *);
int utf8_to_local(char *, u_int, u_char *);
int utf8_valid(const u_char *, u_int);
u_int ucs4_to_utf8(u_int *, u_int, u_char *);
int utf8_to_ucs4(u_int *, u_int, u_char *);
int utf8_to_utf16le(char *, size_t, char **, size_t *);
