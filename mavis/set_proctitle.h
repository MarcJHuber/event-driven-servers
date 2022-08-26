/*
 * set_proctitle.h
 * (C) 2000 Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 */

#ifndef __SET_PROCTITLE_H__
#define __SET_PROCTITLE_H__

#include "misc/sysconf.h"
#include "misc/setproctitle.h"

#define ACCEPT		0
#define ACCEPT_YES	1
#define ACCEPT_NO	2
#define ACCEPT_NEVER	3

void set_proctitle(int);

#endif				/* __SET_PROCTITLE_H__ */
