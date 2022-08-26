/*
 * groups.h
 * (C)1999-2011 by Marc Huber <Marc.Huber@web.de>
 *
 * $Id: groups.h,v 1.7 2011/02/27 12:22:16 marc Exp $
 *
 */

#ifndef __GROUPS_H_
#define __GROUPS_H_
#include <sys/types.h>
#include <grp.h>

char *groups_list2ascii(size_t, gid_t *, char *, size_t);
void groups_ascii2list(char *, int *, gid_t *);
char *groups_getlist(char *, gid_t, char *, size_t);

#endif				/* __GROUPS_H_ */
