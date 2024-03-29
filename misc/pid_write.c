/*
 * pid_write.c
 * (C)2002-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "misc/sysconf.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <ctype.h>
#include <strings.h>
#include <string.h>

static const char rcsid[] __attribute__((used)) = "$Id$";

struct pidfile {
    int fd;
    char path[1];
};

struct pidfile *pid_write(char *path)
{
    struct pidfile *p = NULL;
    if (path && *path) {
	p = calloc(1, sizeof(struct pidfile) + strlen(path));

	strcpy(p->path, path);

	p->fd = open(path, O_WRONLY | O_CREAT | O_NOFOLLOW, S_IROTH | S_IRGRP | S_IWUSR | S_IRUSR);

	if (p->fd > -1) {
	    char s[20];
	    struct flock fl = { .l_type = F_WRLCK, .l_whence = SEEK_SET };
	    size_t l = snprintf(s, sizeof(s), "%lu", (u_long) getpid());

	    if (l < sizeof(s) && (ssize_t) l == write(p->fd, s, l)
		&& !fchmod(p->fd, S_IROTH | S_IRGRP | S_IWUSR | S_IRUSR)
		&& !fcntl(p->fd, F_SETLK, &fl))
		return p;
	    close(p->fd);
	    unlink(path);
	}

	free(p);
	p = NULL;
    }

    return p;
}

void pid_unlink(struct pidfile **p)
{
    if (*p) {
	struct stat s1, s2;
	if (!fstat((*p)->fd, &s1) && !stat((*p)->path, &s2)
	    && s1.st_dev == s2.st_dev && s1.st_ino == s2.st_ino && s1.st_uid == s2.st_uid) {
	    unlink((*p)->path);
	    close((*p)->fd);
	    free(*p);
	    *p = NULL;
	}
    }
}
