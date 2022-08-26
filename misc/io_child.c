/*
  * io_child.c
  * (C)2006-2011 by Marc Huber <Marc.Huber@web.de>
  * All rights reserved.
  *
  * $Id$
  *
 */

#include "misc/sysconf.h"

#include <unistd.h>
#include <stdlib.h>
#include <sysexits.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "misc/io_child.h"


struct io_child_struct {
    pid_t pid;
    void (*fun)(pid_t pid, void *ctx, int status);
    void *ctx;
    struct io_child_struct *next;
};

static struct io_child_struct *list = NULL;

pid_t io_child_fork(void (*fun)(pid_t, void *, int), void *ctx)
{
    pid_t pid = fork();
    switch (pid) {
    case 0:
	while (list) {
	    struct io_child_struct *t = list;
	    list = list->next;
	    free(t);
	}
    case -1:
	break;
    default:
	{
	    struct io_child_struct *t = calloc(1, sizeof(struct io_child_struct));
	    if (!t)
		exit(EX_OSERR);
	    t->pid = pid;
	    t->fun = fun;
	    t->ctx = ctx;
	    t->next = list;
	    list = t;
	}
    }
    return pid;
}

void io_child_reap(void)
{
    pid_t pid;
    int status;

    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
	struct io_child_struct **l = &list;
	struct io_child_struct *t;

	while (*l && (*l)->pid != pid)
	    l = &(*l)->next;
	if (*l) {
	    t = *l;
	    if (t->fun)
		t->fun(t->pid, t->ctx, status);
	    *l = t->next;
	    free(t);
	}
    }
}

void io_child_ign(pid_t pid)
{
    if (pid) {
	struct io_child_struct **l = &list;
	struct io_child_struct *t;

	while (*l && (*l)->pid != pid)
	    l = &(*l)->next;
	if (*l) {
	    t = *l;
	    *l = (*l)->next;
	    free(t);
	}
    }
}

void io_child_set(pid_t pid, void (*fun)(pid_t, void *, int), void *ctx)
{
    struct io_child_struct *l = list;

    while (l && l->pid != pid)
	l = l->next;
    if (l) {
	l->fun = fun;
	l->ctx = ctx;
    }
}
