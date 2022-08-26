/* setproctitle.h
 * (C) 2000 Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id: setproctitle.h,v 1.3 2005/12/31 12:14:23 huber Exp $
 *
 */

#ifndef __SETPROCTITLE_H__
#define __SETPROCTITLE_H__
#include "sysconf.h"
#ifdef HAVE_SETPROCTITLE
#include <sys/types.h>
#include <unistd.h>
#else
void setproctitle(const char *, ...)
    __attribute__((format(printf, 1, 2)));
#endif
void setproctitle_init(char **, char **);
#endif				/* __SETPROCTITLE_H__ */
