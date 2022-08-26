/*
  * io_child.h
  * (C)2006-2011 by Marc Huber <Marc.Huber@web.de>
  * All rights reserved.
  *
  * $Id: io_child.h,v 1.6 2011/07/17 19:12:19 marc Exp $
  *
 */

#ifndef __IO_CHILD_H__
#define __IO_CHILD_H__

#include "misc/sysconf.h"
#include "misc/io_child.h"

pid_t io_child_fork(void (*)(pid_t, void *, int), void *);
void io_child_set(pid_t, void (*)(pid_t, void *, int), void *);
void io_child_reap(void);
void io_child_ign(pid_t);

#endif
