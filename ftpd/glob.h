/*
 * glob.h 
 * (C) 2000-2011 Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id: glob.h,v 1.6 2011/02/27 12:22:16 marc Exp $
 *
 */

#ifndef __GLOB_H__
#define __GLOB_H__
#include <sys/types.h>

struct glob_pattern;

struct glob_pattern *glob_comp(char *);
int glob_exec(struct glob_pattern *, char *);
void glob_free(struct glob_pattern *);

#endif				/* __GLOB_H__ */
