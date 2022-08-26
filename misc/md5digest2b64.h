/*
 * md5digest2b64.h
 * (C) 2000 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id: md5digest2b64.h,v 1.4 2011/07/17 19:12:19 marc Exp $
 *
 */

#ifndef __MD5DIGEST2B64_H__
#define __MD5DIGEST2B64_H__
#include <sys/types.h>
#include "misc/base64.h"

char *md5digest2b64(u_char *, char *);

#endif				/* __MD5DIGEST2B64_H__ */
