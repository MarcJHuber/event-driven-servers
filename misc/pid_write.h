/*
 * pid_write.h
 * (C)2002-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id: pid_write.h,v 1.8 2011/06/26 08:33:28 marc Exp $
 *
 */

#ifndef __PID_WRITE_H__
#define __PID_WRITE_H__
#include <sys/types.h>
struct pidfile;
struct pidfile *pid_write(char *);
void pid_unlink(struct pidfile **);
#endif
