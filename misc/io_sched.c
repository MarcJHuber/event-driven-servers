/*
 * io_sched.c
 * (C)2001-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#define __IO_SCHED_C__

#include "misc/sysconf.h"

#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <sysexits.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

#include "misc/io_sched.h"
#include "misc/rb.h"
#include "mavis/debug.h"
#include "mavis/log.h"
#include "misc/memops.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

#ifdef WITH_KQUEUE
#include <sys/event.h>
#endif
#ifdef WITH_EPOLL
#include <sys/epoll.h>
#endif
#ifdef WITH_POLL
#ifdef WITH_SYSPOLL
#include <sys/poll.h>
#else
#include <poll.h>
#endif
#endif
#ifdef WITH_DEVPOLL
#include <sys/devpoll.h>
#endif
#ifdef WITH_SELECT
#include <sys/select.h>
#endif
#ifdef WITH_PORT
#include <port.h>
#endif

#define IO_MODE_kqueue	(1 << 0)
#define IO_MODE_devpoll	(1 << 1)
#define IO_MODE_epoll	(1 << 2)
#define IO_MODE_poll	(1 << 3)
#define IO_MODE_select	(1 << 4)
#define IO_MODE_port	(1 << 5)

#define ARRAYINC 128
#define LISTINC 128

struct io_handler {
    void *i;			/* input handler */
    void *o;			/* output handler */
    void *i_app;		/* application input handler */
    void *o_app;		/* application output handler */
    void *e;			/* error handler */
    void *h;			/* hangup handler */
    u_int want_read:1;		/* interested in reading */
    u_int want_write:1;		/* interested in writing */
    u_int want_read_app:1;	/* App interested in reading */
    u_int want_write_app:1;	/* App interested in writing */
    u_int want_read_ssl:1;	/* TLS interested in reading */
    u_int want_write_ssl:1;	/* TLS interested in writing */
    u_int reneg:1;		/* TLS renegotiation active */
    void *data;			/* opaque context information */
};

#ifdef WITH_KQUEUE
struct kqueue_io_context {
    struct kevent *changelist;
    struct kevent *eventlist;
    int nchanges;
    int nchanges_max;
    int nevents_max;
    int fd;
};
#endif

#ifdef WITH_EPOLL
struct epoll_io_context {
    int *changelist;
    int *changemap;
    int *diskfilemap;
    int *diskfile;
    struct epoll_event *eventlist;
    int nchanges;
    int ndiskfile;
    int nevents_max;
    int fd;
};
#endif

#ifdef WITH_DEVPOLL
struct devpoll_io_context {
    struct pollfd *changelist;
    struct pollfd *eventlist;
    int nchanges;
    int nchanges_max;
    int nevents_max;
    int fd;
};
#endif

#ifdef WITH_POLL
struct poll_io_context {
    struct pollfd *ufds;
    int nfds;
    int *pax;
};
#endif

#ifdef WITH_SELECT
struct select_io_context {
    fd_set rfds;
    fd_set wfds;
    fd_set efds;
    int nfds;
};
#endif

#ifdef WITH_PORT
struct port_io_context {
    int *changelist;
    int *changemap;
    port_event_t *eventlist;
    int nchanges;
    int fd;
    int nfds;
    int nevents_max;
};
#endif

struct event_cache {
    int fd;
    int events;
};

struct io_context {
    struct io_handler *handler;
    rb_tree_t *events_by_data;
    rb_tree_t *events_by_time;
    void *io_invalid_i;
    void *io_invalid_o;
    void *io_invalid_h;
    void *io_invalid_e;
    int *rcache_map;		/* fd -> rcache map index */
    struct event_cache *rcache;
    int nfds_limit;
    int nfds_max;
    union {
#ifdef WITH_SELECT
	struct select_io_context select;
#define Select mechanism.select
#endif
#ifdef WITH_POLL
	struct poll_io_context poll;
#define Poll mechanism.poll
#endif
#ifdef WITH_EPOLL
	struct epoll_io_context epoll;
#define Epoll mechanism.epoll
#endif
#ifdef WITH_DEVPOLL
	struct devpoll_io_context devpoll;
#define Devpoll mechanism.devpoll
#endif
#ifdef WITH_KQUEUE
	struct kqueue_io_context kqueue;
#define Kqueue mechanism.kqueue
#endif
#ifdef WITH_PORT
	struct port_io_context port;
#define Port mechanism.port
#endif
    } mechanism;
};

struct io_event {
    void *proc;
    struct timeval time_wait;
    struct io_event *next;
};

struct io_sched {
    void *data;			/* context pointer, e.g. */
    struct timeval time_when;	/* when next event is triggered */
    struct timeval time_real;	/* when next event should be triggered */
    struct io_event *event;	/* event pointer */
};

static void (*mech_io_set_i)(struct io_context *, int);
static void (*mech_io_set_o)(struct io_context *, int);
static void (*mech_io_clr_i)(struct io_context *, int);
static void (*mech_io_clr_o)(struct io_context *, int);
static void (*mech_io_register)(struct io_context *, int);
static void (*mech_io_unregister)(struct io_context *, int);
static void (*mech_io_close)(struct io_context *, int);
static void (*mech_io_destroy)(struct io_context *);
static int (*mech_io_poll)(struct io_context *, int, int *);
static void (*mech_io_poll_finish)(struct io_context *, int);

static void io_resize(struct io_context *, int fd);

static __inline__ int MINIMUM(int a, int b)
{
    return (a < b) ? a : b;
}

static __inline__ int MAXIMUM(int a, int b)
{
    return (a < b) ? b : a;
}

#define SIOS(A) ((struct io_sched *)(A))

static int cmp_tv(const void *a, const void *b)
{
    if (SIOS(a)->time_when.tv_sec < SIOS(b)->time_when.tv_sec)
	return -1;
    if (SIOS(a)->time_when.tv_sec > SIOS(b)->time_when.tv_sec)
	return +1;
    if (SIOS(a)->time_when.tv_usec < SIOS(b)->time_when.tv_usec)
	return -1;
    if (SIOS(a)->time_when.tv_usec > SIOS(b)->time_when.tv_usec)
	return +1;
    if (a < b)
	return -1;
    if (a > b)
	return +1;
    return 0;
}

static int cmp_data(const void *a, const void *b)
{
    if (SIOS(a)->data < SIOS(b)->data)
	return -1;
    if (SIOS(a)->data > SIOS(b)->data)
	return +1;
    return 0;
}

static void io_invalid_i(void *v __attribute__((unused)), int cur)
{
    logmsg("io_invalid_i (%d)", cur);
    abort();
}

static void io_invalid_o(void *v __attribute__((unused)), int cur)
{
    logmsg("io_invalid_o (%d)", cur);
    abort();
}

static void io_invalid_e(void *v __attribute__((unused)), int cur)
{
    logmsg("io_invalid_e (%d)", cur);
    abort();
}

static void io_invalid_h(void *v __attribute__((unused)), int cur)
{
    logmsg("io_invalid_h (%d)", cur);
    abort();
}

int io_is_invalid_i(struct io_context *io, int cur)
{
    if (cur < 0)
	return -1;

    return (io->handler[cur].i_app == io->io_invalid_i);
}

int io_is_invalid_o(struct io_context *io, int cur)
{
    if (cur < 0)
	return -1;

    return (io->handler[cur].o_app == io->io_invalid_o);
}

int io_is_invalid_e(struct io_context *io, int cur)
{
    if (cur < 0)
	return -1;

    return (io->handler[cur].e == io->io_invalid_e);
}

int io_is_invalid_h(struct io_context *io, int cur)
{
    if (cur < 0)
	return -1;

    return (io->handler[cur].h == io->io_invalid_h);
}

int io_poll(struct io_context *io, int poll_timeout)
{
    int count, cax = 0;
    int res = mech_io_poll(io, poll_timeout, &cax);

    for (count = 0; count < cax; count++) {
	int cur = io->rcache[count].fd;
	struct io_context *ctx;

	if (cur > -1) {
	    ctx = io_get_ctx(io, cur);
	    Debug((DEBUG_PROC, "fd %d ctx %p\n", cur, ctx));
	    if (ctx) {
		void (*cb)(void *, int);
		if (io->handler[cur].want_read && (io->rcache[count].events & POLLIN))
		    cb = (void (*)(void *, int)) (io_get_cb_i(io, cur));
		else if (io->handler[cur].want_write && (io->rcache[count].events & POLLOUT)
			 && !(io->rcache[count].events & POLLHUP))
		    cb = (void (*)(void *, int)) (io_get_cb_o(io, cur));
		else if (io->rcache[count].events & POLLERR)
		    cb = (void (*)(void *, int)) (io_get_cb_e(io, cur));
		else if (io->rcache[count].events & POLLHUP)
		    cb = (void (*)(void *, int)) (io_get_cb_h(io, cur));
		else
		    cb = NULL;

		Debug((DEBUG_PROC, "fd %d cb = %p\n", cur, cb));
		if (cb)
		    cb(ctx, cur);
	    }
	    io->rcache_map[cur] = -1;
	}

	io->rcache[count].fd = -1;
	io->rcache[count].events = 0;
    }
    if (mech_io_poll_finish)
	mech_io_poll_finish(io, res);

    return res;
}

struct io_context *io_destroy(struct io_context *io, void (*freeproc)(void *))
{
    if (io) {
	RB_tree_delete(io->events_by_data);
	RB_tree_delete(io->events_by_time);

	if (freeproc) {
	    int i;
	    for (i = 0; i < io->nfds_max; i++)
		if (io->handler[i].data)
		    freeproc(io->handler[i].data);
	}

	mech_io_destroy(io);

	free(io->handler);
	free(io->rcache_map);
	free(io->rcache);
	free(io);
    }
    return NULL;
}

void io_register(struct io_context *io, int fd, void *data)
{
    if (fd < 0)
	return;

    mech_io_register(io, fd);

    io->handler[fd].data = data;
    io->handler[fd].i = io->io_invalid_i;
    io->handler[fd].o = io->io_invalid_o;
    io->handler[fd].i_app = io->io_invalid_i;
    io->handler[fd].o_app = io->io_invalid_o;
    io->handler[fd].e = io->io_invalid_e;
    io->handler[fd].h = io->io_invalid_h;
    io->handler[fd].want_read = 0;
    io->handler[fd].want_write = 0;
    io->handler[fd].want_read_app = 0;
    io->handler[fd].want_write_app = 0;
#if defined(WITH_SSL) || defined(WITH_TLS)
    io->handler[fd].want_read_ssl = 0;
    io->handler[fd].want_write_ssl = 0;
#endif
}

void *io_unregister(struct io_context *io, int fd)
{
    if (fd < 0)
	return NULL;

    void *res = io->handler[fd].data;

    mech_io_unregister(io, fd);

    io->handler[fd].data = NULL;
    io->handler[fd].want_read = 0;
    io->handler[fd].want_write = 0;

    if (io->rcache_map[fd] > -1) {
	io->rcache[io->rcache_map[fd]].fd = -1;
	io->rcache[io->rcache_map[fd]].events = 0;
	io->rcache_map[fd] = -1;
    }

    return res;
}

int io_close(struct io_context *io, int fd)
{
    if (fd < 0)
	return -1;

    io_unregister(io, fd);
    if (mech_io_close)
	mech_io_close(io, fd);
    return close(fd);
}

void io_set_i(struct io_context *io, int fd)
{
    if (fd < 0)
	return;

    if (!io->handler[fd].want_read_app) {
	io->handler[fd].want_read_app = 1;
	mech_io_set_i(io, fd);
    }
}

void io_set_o(struct io_context *io, int fd)
{
    if (fd < 0)
	return;

    if (!io->handler[fd].want_write_app) {
	io->handler[fd].want_write_app = 1;
	mech_io_set_o(io, fd);
    }
}

void io_clr_i(struct io_context *io, int fd)
{
    if (fd < 0)
	return;

    if (io->handler[fd].want_read_app) {
	io->handler[fd].want_read_app = 0;
#if defined(WITH_SSL) || defined(WITH_TLS)
	if (io->handler[fd].want_read_ssl)
	    return;
#endif
	mech_io_clr_i(io, fd);

	if (io->rcache_map[fd] > -1)
	    io->rcache[io->rcache_map[fd]].events &= ~POLLIN;
    }
}

void io_clr_o(struct io_context *io, int fd)
{
    if (fd < 0)
	return;

    if (io->handler[fd].want_write_app) {
	io->handler[fd].want_write_app = 0;
#if defined(WITH_SSL) || defined(WITH_TLS)
	if (io->handler[fd].want_write_ssl)
	    return;
#endif
	mech_io_clr_o(io, fd);
	if (io->rcache_map[fd] > -1)
	    io->rcache[io->rcache_map[fd]].events &= ~POLLOUT;
    }
}

#if defined(WITH_SSL) || defined(WITH_TLS)
static __inline__ void io_SSL_set_i(struct io_context *io, int fd)
{
    if (fd < 0)
	return;

    if (!io->handler[fd].want_read_ssl) {
	io->handler[fd].want_read_ssl = 1;
	mech_io_set_i(io, fd);
    }
}

static __inline__ void io_SSL_set_o(struct io_context *io, int fd)
{
    if (fd < 0)
	return;

    if (!io->handler[fd].want_write_ssl) {
	io->handler[fd].want_write_ssl = 1;
	mech_io_set_o(io, fd);
    }
}

static __inline__ void io_SSL_clr_i(struct io_context *io, int fd)
{
    if (fd < 0)
	return;

    if (io->handler[fd].want_read_ssl) {
	io->handler[fd].want_read_ssl = 0;
	if (!io->handler[fd].want_read_app)
	    mech_io_clr_i(io, fd);
    }
}

static __inline__ void io_SSL_clr_o(struct io_context *io, int fd)
{
    if (fd < 0)
	return;

    if (io->handler[fd].want_write_ssl) {
	io->handler[fd].want_write_ssl = 0;
	if (!io->handler[fd].want_write_app)
	    mech_io_clr_o(io, fd);
    }
}
#endif				/* WITH_SSL */

#ifdef WITH_SELECT
static void select_io_set_i(struct io_context *io, int fd)
{
    io->handler[fd].want_read = 1;
    FD_SET(fd, &io->Select.rfds);
}

static void select_io_set_o(struct io_context *io, int fd)
{
    io->handler[fd].want_write = 1;
    FD_SET(fd, &io->Select.wfds);
}

static void select_io_clr_i(struct io_context *io, int fd)
{
    io->handler[fd].want_read = 0;
    FD_CLR(fd, &io->Select.rfds);
}

static void select_io_clr_o(struct io_context *io, int fd)
{
    io->handler[fd].want_write = 0;
    FD_CLR(fd, &io->Select.wfds);
}

static void select_io_init(struct io_context *io)
{
    FD_ZERO(&io->Select.rfds);
    FD_ZERO(&io->Select.wfds);
    FD_ZERO(&io->Select.efds);
    io->Select.nfds = -1;
}

static int select_io_poll(struct io_context *io, int poll_timeout, int *cax)
{
    int cur = 0, r, res;
    struct timeval timeout;
    fd_set rfds, wfds, efds;

    Debug((DEBUG_PROC, "io_poll (%p, %dms)\n", io, poll_timeout));

    *cax = 0;

    timeout.tv_sec = poll_timeout / 1000;
    timeout.tv_usec = 1000 * (u_int) (poll_timeout - 1000 * timeout.tv_sec);
    rfds = io->Select.rfds;
    wfds = io->Select.wfds;
    efds = io->Select.efds;

    r = res = select(io->Select.nfds + 1, &rfds, &wfds, &efds, poll_timeout < 0 ? NULL : &timeout);

    if (r < 0) {
	logerr("Fatal select(2) error (%ld, ..., (%lu, %lu))", (long int) io->Select.nfds + 1, (u_long) timeout.tv_sec, (u_long) timeout.tv_usec);
	abort();
    }

    gettimeofday(&io_now, NULL);

    for (; r > 0 && cur < io->nfds_max; cur++) {
	if (FD_ISSET(cur, &rfds) || FD_ISSET(cur, &wfds) || FD_ISSET(cur, &efds)) {
	    if (io->rcache_map[cur] < 0) {
		io->rcache[*cax].events = 0;
		io->rcache[*cax].fd = cur;
		io->rcache_map[cur] = (*cax)++;
	    }

	    if (FD_ISSET(cur, &rfds))
		r--, io->rcache[io->rcache_map[cur]].events |= POLLIN;
	    if (FD_ISSET(cur, &efds))
		r--, io->rcache[io->rcache_map[cur]].events |= POLLERR;
	    if (FD_ISSET(cur, &wfds))
		r--, io->rcache[io->rcache_map[cur]].events |= POLLOUT;

	    if (r < 0) {
		logmsg("Bug near %s:%d", __FILE__, __LINE__);
		abort();
	    }
	}
    }

    return res;
}

static void select_io_destroy(struct io_context *io __attribute__((unused)))
{
    /* nothing to do */
}

static void select_io_unregister(struct io_context *io, int fd)
{
    Debug((DEBUG_PROC, " io_unregister %d\n", fd));

    FD_CLR(fd, &io->Select.rfds);
    FD_CLR(fd, &io->Select.wfds);
    FD_CLR(fd, &io->Select.efds);

    if (fd == io->Select.nfds)
	do
	    io->Select.nfds--;
	while (io->Select.nfds > -1 && io->handler[io->Select.nfds].data == NULL);
}

static void select_io_register(struct io_context *io, int fd)
{
    Debug((DEBUG_PROC, " io_register %d\n", fd));

    if (fd >= io->nfds_max)
	io_resize(io, fd);

    if (fd > io->Select.nfds)
	io->Select.nfds = fd;

    FD_SET(fd, &io->Select.efds);
}
#endif

#ifdef WITH_POLL
static void poll_io_set_i(struct io_context *io, int fd)
{
    if (!io->handler[fd].want_read) {
	io->handler[fd].want_read = 1;
	io->Poll.ufds[io->Poll.pax[fd]].events |= POLLIN;
    }
}

static void poll_io_set_o(struct io_context *io, int fd)
{
    if (!io->handler[fd].want_write) {
	io->handler[fd].want_write = 1;
	io->Poll.ufds[io->Poll.pax[fd]].events |= POLLOUT;
    }
}

static void poll_io_clr_i(struct io_context *io, int fd)
{
    if (io->handler[fd].want_read) {
	io->handler[fd].want_read = 0;
	io->Poll.ufds[io->Poll.pax[fd]].events &= ~POLLIN;
    }
}

static void poll_io_clr_o(struct io_context *io, int fd)
{
    if (io->handler[fd].want_write) {
	io->handler[fd].want_write = 0;
	io->Poll.ufds[io->Poll.pax[fd]].events &= ~POLLOUT;
    }
}

static void poll_io_init(struct io_context *io)
{
    int i;

    io->Poll.ufds = Xcalloc(io->nfds_max, sizeof(struct pollfd));
    io->Poll.pax = Xcalloc(io->nfds_max, sizeof(int));
    for (i = 0; i < io->nfds_max; i++)
	io->Poll.pax[i] = -1;
}

static int poll_io_poll(struct io_context *io, int poll_timeout, int *cax)
{
    int count, res, r;
    Debug((DEBUG_PROC, "io_poll (%p) timeout: %d\n", io, poll_timeout));

    *cax = 0;

    r = res = poll(io->Poll.ufds, (nfds_t) (io->Poll.nfds), poll_timeout);

    Debug((DEBUG_PROC, "io_poll (%p) timeout: %d, res: %d\n", io, poll_timeout, res));

    gettimeofday(&io_now, NULL);

    for (count = io->Poll.nfds - 1; r > 0 && count > -1; count--) {
	int cur = io->Poll.ufds[count].fd;

	if (cur > -1 && io->Poll.pax[cur] > -1 && io->Poll.ufds[io->Poll.pax[cur]].revents) {
	    r--;

	    if (io->rcache_map[cur] < 0) {
		io->rcache[*cax].events = 0;
		io->rcache[*cax].fd = cur;
		io->rcache_map[cur] = (*cax)++;
	    }

	    io->rcache[io->rcache_map[cur]].events = io->Poll.ufds[io->Poll.pax[cur]].revents;
	}
    }

    return res;
}

static void poll_io_destroy(struct io_context *io)
{
    free(io->Poll.ufds);
    free(io->Poll.pax);
}

static void poll_io_unregister(struct io_context *io, int fd)
{
    int pos = io->Poll.pax[fd];
    Debug((DEBUG_PROC, " io_unregister %d\n", fd));

    if (pos < 0 || pos >= io->Poll.nfds) {
	logmsg("Ooops ... poll array index for %d out of range (%d)!", fd, pos);
	abort();
    }

    if (pos != --io->Poll.nfds) {
	io->Poll.ufds[pos] = io->Poll.ufds[io->Poll.nfds];
	io->Poll.pax[io->Poll.ufds[pos].fd] = pos;
    }

    io->Poll.pax[fd] = -1;
}

static void poll_io_register(struct io_context *io, int fd)
{
    Debug((DEBUG_PROC, " io_register %d\n", fd));

    if (fd >= io->nfds_max) {
	int i;
	int omax = io->nfds_max;
	io_resize(io, fd);
	io->Poll.ufds = Xrealloc(io->Poll.ufds, io->nfds_max * sizeof(struct pollfd));
	io->Poll.pax = Xrealloc(io->Poll.pax, io->nfds_max * sizeof(int));
	for (i = omax; i < io->nfds_max; i++)
	    io->Poll.pax[i] = -1;
    }

    if (io->Poll.pax[fd] != -1) {
	logmsg("Ooops ... poll array index for %d already set!", fd);
	logmsg("%d %d %d", io->nfds_limit, io->nfds_max, fd);
	abort();
    }

    memset(&io->Poll.ufds[io->Poll.nfds], 0, sizeof(struct pollfd));
    io->Poll.ufds[io->Poll.nfds].fd = fd;
    io->Poll.ufds[io->Poll.nfds].events = 0;
    io->Poll.pax[fd] = io->Poll.nfds++;
}
#endif

#ifdef WITH_EPOLL
static void epoll_io_close(struct io_context *io, int fd)
{
    if (io->Epoll.changemap[fd] > -1) {
	io->Epoll.changelist[io->Epoll.changemap[fd]] = -1;
	io->Epoll.changemap[fd] = -1;
	io->Epoll.nchanges--;
    }
}

static void epoll_addchange(struct io_context *io, int fd)
{
    if (io->Epoll.changemap[fd] < 0 || io->Epoll.changemap[fd] >= io->Epoll.nchanges || io->Epoll.changelist[io->Epoll.changemap[fd]] != fd) {
	io->Epoll.changemap[fd] = io->Epoll.nchanges;
	io->Epoll.changelist[io->Epoll.nchanges++] = fd;
    }
}

static void epoll_io_set_i(struct io_context *io, int fd)
{
    if (!io->handler[fd].want_read) {
	io->handler[fd].want_read = 1;
	if (io->Epoll.diskfile[fd] == -2) {
	    io->Epoll.diskfilemap[io->Epoll.ndiskfile] = fd;
	    io->Epoll.diskfile[fd] = io->Epoll.ndiskfile++;
	} else if (io->Epoll.diskfile[fd] == -1)
	    epoll_addchange(io, fd);
    }
}

static void epoll_io_clr_i(struct io_context *io, int fd)
{
    if (io->handler[fd].want_read) {
	io->handler[fd].want_read = 0;
	if (io->Epoll.diskfile[fd] > -1) {
	    if (!io->handler[fd].want_write) {
		io->Epoll.ndiskfile--;
		io->Epoll.diskfilemap[io->Epoll.diskfile[fd]] = io->Epoll.diskfilemap[io->Epoll.ndiskfile];
		io->Epoll.diskfile[io->Epoll.diskfilemap[io->Epoll.ndiskfile]] = io->Epoll.diskfile[fd];
		io->Epoll.diskfile[fd] = -2;
	    }
	} else
	    epoll_addchange(io, fd);
    }
}

static void epoll_io_set_o(struct io_context *io, int fd)
{
    if (!io->handler[fd].want_write) {
	io->handler[fd].want_write = 1;
	if (io->Epoll.diskfile[fd] == -2) {
	    io->Epoll.diskfilemap[io->Epoll.ndiskfile] = fd;
	    io->Epoll.diskfile[fd] = io->Epoll.ndiskfile++;
	} else if (io->Epoll.diskfile[fd] == -1)
	    epoll_addchange(io, fd);
    }
}

static void epoll_io_clr_o(struct io_context *io, int fd)
{
    if (io->handler[fd].want_write) {
	io->handler[fd].want_write = 0;
	if (io->Epoll.diskfile[fd] > -1) {
	    if (!io->handler[fd].want_read) {
		io->Epoll.ndiskfile--;
		io->Epoll.diskfilemap[io->Epoll.diskfile[fd]] = io->Epoll.diskfilemap[io->Epoll.ndiskfile];
		io->Epoll.diskfile[io->Epoll.diskfilemap[io->Epoll.ndiskfile]] = io->Epoll.diskfile[fd];
		io->Epoll.diskfile[fd] = -2;
	    }
	} else
	    epoll_addchange(io, fd);
    }
}

static void epoll_io_init(struct io_context *io)
{
    int i, flags;

    io->Epoll.fd = epoll_create(io->nfds_max);

    flags = fcntl(io->Epoll.fd, F_GETFD, 0) | FD_CLOEXEC;
    fcntl(io->Epoll.fd, F_SETFD, flags);

    io->Epoll.nchanges = io->Epoll.ndiskfile = 0;
    io->Epoll.nevents_max = io->nfds_max;
    io->Epoll.eventlist = Xcalloc(io->Epoll.nevents_max, sizeof(struct epoll_event));
    io->Epoll.changelist = Xcalloc(io->nfds_max, sizeof(int));
    io->Epoll.changemap = Xcalloc(io->nfds_max, sizeof(int));
    io->Epoll.diskfile = Xcalloc(io->nfds_max, sizeof(int));
    io->Epoll.diskfilemap = Xcalloc(io->nfds_max, sizeof(int));
    for (i = 0; i < io->nfds_max; i++) {
	io->Epoll.changelist[i] = -1;
	io->Epoll.changemap[i] = -1;
	io->Epoll.diskfile[i] = -1;
	io->Epoll.diskfilemap[i] = -1;
    }
}

static void epoll_io_unregister(struct io_context *io __attribute__((unused)), int fd __attribute__((unused)))
{
    Debug((DEBUG_PROC, " io_unregister %d\n", fd));
    if (io->Epoll.diskfile[fd] > -1) {
	io->Epoll.ndiskfile--;
	io->Epoll.diskfilemap[io->Epoll.diskfile[fd]] = io->Epoll.diskfilemap[io->Epoll.ndiskfile];
	io->Epoll.diskfile[io->Epoll.diskfilemap[io->Epoll.ndiskfile]] = io->Epoll.diskfile[fd];
	io->Epoll.diskfile[fd] = -1;
    }
}

static void epoll_io_register(struct io_context *io, int fd)
{
    struct epoll_event e;
    Debug((DEBUG_PROC, " io_register %d\n", fd));

    if (fd >= io->nfds_max) {
	int i;
	int omax = io->nfds_max;
	io_resize(io, fd);
	io->Epoll.changelist = Xrealloc(io->Epoll.changelist, io->nfds_max * sizeof(int));
	io->Epoll.changemap = Xrealloc(io->Epoll.changemap, io->nfds_max * sizeof(int));
	io->Epoll.diskfile = Xrealloc(io->Epoll.diskfile, io->nfds_max * sizeof(int));
	io->Epoll.diskfilemap = Xrealloc(io->Epoll.diskfile, io->nfds_max * sizeof(int));
	for (i = omax; i < io->nfds_max; i++) {
	    io->Epoll.changelist[i] = -1;
	    io->Epoll.changemap[i] = -1;
	    io->Epoll.diskfile[i] = -1;
	    io->Epoll.diskfilemap[i] = -1;
	}
    }

    e.data.fd = fd;
    e.events = 0;
    if (-1 == epoll_ctl(io->Epoll.fd, EPOLL_CTL_ADD, fd, &e)
	&& errno == EPERM)
	io->Epoll.diskfile[fd] = -2;
}

static int epoll_io_poll(struct io_context *io, int poll_timeout, int *cax)
{
    int count, res;
    Debug((DEBUG_PROC, "io_poll (%p)\n", io));

    *cax = 0;

    for (count = 0; count < io->Epoll.nchanges; count++) {
	int fd = io->Epoll.changelist[count];
	if (fd > -1 && io->Epoll.changemap[fd] == count && io->Epoll.diskfilemap[fd] == -1) {
	    struct epoll_event e;
	    e.data.fd = fd;
	    e.events = (io->handler[fd].want_read ? EPOLLIN : 0) | (io->handler[fd].want_write ? EPOLLOUT : 0);
	    if (epoll_ctl(io->Epoll.fd, EPOLL_CTL_MOD, fd, &e) < 0) {
#ifndef DEBUG
		logerr("epoll_ctl (%s:%d)", __FILE__, __LINE__)
#endif
		    ;
	    }
	    io->Epoll.changemap[fd] = -1;
	}
    }
    io->Epoll.nchanges = 0;

    res = epoll_wait(io->Epoll.fd, io->Epoll.eventlist, io->Epoll.nevents_max, /* io->Epoll.ndiskfile ? 0 : */ poll_timeout);

    gettimeofday(&io_now, NULL);

    for (count = 0; count < res; count++) {
	int cur = io->Epoll.eventlist[count].data.fd;

	if (io->rcache_map[cur] < 0) {
	    io->rcache[*cax].events = 0;
	    io->rcache[*cax].fd = cur;
	    io->rcache_map[cur] = (*cax)++;
	}

	io->rcache[io->rcache_map[cur]].events = io->Epoll.eventlist[count].events;
    }

    res += io->Epoll.ndiskfile;

    for (count = 0; count < io->Epoll.ndiskfile; count++) {
	int cur = io->Epoll.diskfilemap[count];

	if (io->rcache_map[cur] < 0) {
	    io->rcache[*cax].events = 0;
	    io->rcache[*cax].fd = cur;
	    io->rcache_map[cur] = (*cax)++;
	}

	if (io->handler[cur].want_write)
	    io->rcache[io->rcache_map[cur]].events |= POLLOUT;
	if (io->handler[cur].want_read)
	    io->rcache[io->rcache_map[cur]].events |= POLLIN;
    }

    return res;
}

static void epoll_io_destroy(struct io_context *io)
{
    free(io->Epoll.eventlist);
    free(io->Epoll.changelist);
    free(io->Epoll.changemap);
    free(io->Epoll.diskfile);
    free(io->Epoll.diskfilemap);
    close(io->Epoll.fd);
}
#endif

#ifdef WITH_DEVPOLL
static void devpoll_io_changelist_resize(struct io_context *io)
{
    io->Devpoll.nchanges_max += LISTINC;
    io->Devpoll.changelist = Xrealloc(io->Devpoll.changelist, io->Devpoll.nchanges_max * sizeof(struct pollfd));
}

static void devpoll_io_close(struct io_context *io, int fd)
{
    int i, j;
    for (i = 0, j = 0; i < io->Devpoll.nchanges; i++) {
	if ((int) io->Devpoll.changelist[i].fd == fd)
	    continue;
	if (i != j)
	    io->Devpoll.changelist[j] = io->Devpoll.changelist[i];
	j++;
    }
    io->Devpoll.nchanges = j;
}

static void devpoll_io_set_i(struct io_context *io, int fd)
{
    if (!io->handler[fd].want_read) {
	io->handler[fd].want_read = 1;
	if (io->Devpoll.nchanges == io->Devpoll.nchanges_max)
	    devpoll_io_changelist_resize(io);

	io->Devpoll.changelist[io->Devpoll.nchanges].fd = fd;
	io->Devpoll.changelist[io->Devpoll.nchanges++].events = POLLIN;
    }
}

static void devpoll_io_set_o(struct io_context *io, int fd)
{
    if (!io->handler[fd].want_write) {
	io->handler[fd].want_write = 1;
	if (io->Devpoll.nchanges == io->Devpoll.nchanges_max)
	    devpoll_io_changelist_resize(io);

	io->Devpoll.changelist[io->Devpoll.nchanges].fd = fd;
	io->Devpoll.changelist[io->Devpoll.nchanges++].events = POLLOUT;
    }
}

static void devpoll_io_clr_i(struct io_context *io, int fd)
{
    if (io->handler[fd].want_read) {
	io->handler[fd].want_read = 0;
	if (io->Devpoll.nchanges == io->Devpoll.nchanges_max)
	    devpoll_io_changelist_resize(io);

	io->Devpoll.changelist[io->Devpoll.nchanges].fd = fd;
	io->Devpoll.changelist[io->Devpoll.nchanges++].events = POLLREMOVE;

	if (io->handler[fd].want_write) {
	    io->handler[fd].want_write = 0;
	    devpoll_io_set_o(io, fd);
	}
    }
}

static void devpoll_io_clr_o(struct io_context *io, int fd)
{
    if (io->handler[fd].want_write) {
	io->handler[fd].want_write = 0;
	if (io->Devpoll.nchanges == io->Devpoll.nchanges_max)
	    devpoll_io_changelist_resize(io);

	io->Devpoll.changelist[io->Devpoll.nchanges].fd = fd;
	io->Devpoll.changelist[io->Devpoll.nchanges++].events = POLLREMOVE;

	if (io->handler[fd].want_read) {
	    io->handler[fd].want_read = 0;
	    devpoll_io_set_i(io, fd);
	}
    }
}

static void devpoll_io_init(struct io_context *io)
{
    int flags;

    if ((io->Devpoll.fd = open("/dev/poll", O_RDWR)) < 0) {
	logerr("devpoll open (%s:%d)", __FILE__, __LINE__);
	abort();
    }
    flags = fcntl(io->Devpoll.fd, F_GETFD, 0) | FD_CLOEXEC;
    fcntl(io->Devpoll.fd, F_SETFD, flags);

    io->Devpoll.nchanges = 0;
    io->Devpoll.nchanges_max = LISTINC;
    io->Devpoll.changelist = Xcalloc(io->Devpoll.nchanges_max, sizeof(struct pollfd));
    io->Devpoll.nevents_max = LISTINC;
    io->Devpoll.eventlist = Xcalloc(io->Devpoll.nevents_max, sizeof(struct pollfd));
}

static int devpoll_io_poll(struct io_context *io, int poll_timeout, int *cax)
{
    int count, res;
    struct dvpoll dvp;

    Debug((DEBUG_PROC, "io_poll (%p)\n", io));

    *cax = 0;

    dvp.dp_fds = io->Devpoll.eventlist;
    dvp.dp_nfds = io->Devpoll.nevents_max;
    dvp.dp_timeout = poll_timeout > -1 ? poll_timeout : 0;

    if (io->Devpoll.nchanges &&
	(write(io->Devpoll.fd, io->Devpoll.changelist,
	       sizeof(struct pollfd) * io->Devpoll.nchanges) != (ssize_t) sizeof(struct pollfd) * io->Devpoll.nchanges)) {
	logerr("devpoll write (%s:%d)", __FILE__, __LINE__);
	abort();
    }

    res = ioctl(io->Devpoll.fd, DP_POLL, &dvp);
    Debug((DEBUG_PROC, "devpoll ioctl returns %d\n", res));

    if (0 > res) {
	logerr("devpoll ioctl (%s:%d)", __FILE__, __LINE__);
	abort();
    }

    io->Devpoll.nchanges = 0;

    gettimeofday(&io_now, NULL);

    for (count = 0; count < res; count++) {
	int cur = io->Devpoll.eventlist[count].fd;

	if (io->rcache_map[cur] < 0) {
	    io->rcache[*cax].events = 0;
	    io->rcache[*cax].fd = cur;
	    io->rcache_map[cur] = (*cax)++;
	}
	io->rcache[io->rcache_map[cur]].events = io->Devpoll.eventlist[count].revents;
    }

    return res;
}

static void devpoll_io_destroy(struct io_context *io)
{
    free(io->Devpoll.changelist);
    free(io->Devpoll.eventlist);
    close(io->Devpoll.fd);
}

static void devpoll_io_unregister(struct io_context *io, int fd)
{
    Debug((DEBUG_PROC, " io_unregister %d\n", fd));

    if (io->handler[fd].want_read || io->handler[fd].want_write) {

	if (io->Devpoll.nchanges == io->Devpoll.nchanges_max)
	    devpoll_io_changelist_resize(io);

	io->Devpoll.changelist[io->Devpoll.nchanges].fd = fd;
	io->Devpoll.changelist[io->Devpoll.nchanges++].events = POLLREMOVE;
    }
}

static void devpoll_io_register(struct io_context *io, int fd)
{
    Debug((DEBUG_PROC, " io_register %d\n", fd));
    if (fd >= io->nfds_max)
	io_resize(io, fd);
}
#endif

#ifdef WITH_KQUEUE
static void kqueue_io_changelist_resize(struct io_context *io)
{
    io->Kqueue.nchanges_max += LISTINC;
    io->Kqueue.changelist = Xrealloc(io->Kqueue.changelist, io->Kqueue.nchanges_max * sizeof(struct kevent));
}

static void kqueue_io_set_i(struct io_context *io, int fd)
{
    Debug((DEBUG_PROC, "io_set_i(%d)\n", fd));
    if (!io->handler[fd].want_read) {
	io->handler[fd].want_read = 1;
	if (io->Kqueue.nchanges == io->Kqueue.nchanges_max)
	    kqueue_io_changelist_resize(io);

	EV_SET(&io->Kqueue.changelist[io->Kqueue.nchanges], fd, EVFILT_READ, EV_ADD, 0, 0,
#ifdef __NetBSD__
	       (intptr_t)
#endif
	       io_get_ctx(io, fd));

	io->Kqueue.nchanges++;
    }
}

static struct timespec *timeout_immediately = NULL;

static void kqueue_flush(struct io_context *io)
{
    kevent(io->Kqueue.fd, io->Kqueue.changelist, io->Kqueue.nchanges, io->Kqueue.eventlist, 0, timeout_immediately);
    io->Kqueue.nchanges = 0;
}

static void kqueue_io_clr_i(struct io_context *io, int fd)
{
    Debug((DEBUG_PROC, "io_clr_i(%d)\n", fd));
    if (io->handler[fd].want_read) {
	io->handler[fd].want_read = 0;
	if (io->Kqueue.nchanges == io->Kqueue.nchanges_max)
	    kqueue_io_changelist_resize(io);

	EV_SET(&io->Kqueue.changelist[io->Kqueue.nchanges], fd, EVFILT_READ, EV_DELETE, 0, 0,
#ifdef __NetBSD__
	       (intptr_t)
#endif
	       NULL);
	io->Kqueue.nchanges++;
    }
}

static void kqueue_io_set_o(struct io_context *io, int fd)
{
    Debug((DEBUG_PROC, "io_set_o(%d)\n", fd));
    if (!io->handler[fd].want_write) {
	io->handler[fd].want_write = 1;
	if (io->Kqueue.nchanges == io->Kqueue.nchanges_max)
	    kqueue_io_changelist_resize(io);

	EV_SET(&io->Kqueue.changelist[io->Kqueue.nchanges], fd, EVFILT_WRITE, EV_ADD, 0, 0,
#ifdef __NetBSD__
	       (intptr_t)
#endif
	       io_get_ctx(io, fd));
	io->Kqueue.nchanges++;
    }
}

static void kqueue_io_clr_o(struct io_context *io, int fd)
{
    Debug((DEBUG_PROC, "io_clr_o(%d)\n", fd));
    if (io->handler[fd].want_write) {
	io->handler[fd].want_write = 0;
	if (io->Kqueue.nchanges == io->Kqueue.nchanges_max)
	    kqueue_io_changelist_resize(io);

	EV_SET(&io->Kqueue.changelist[io->Kqueue.nchanges], fd, EVFILT_WRITE, EV_DELETE, 0, 0,
#ifdef __NetBSD__
	       (intptr_t)
#endif
	       NULL);
	io->Kqueue.nchanges++;
    }
}

static void kqueue_io_init(struct io_context *io)
{
    io->Kqueue.fd = kqueue();
    io->Kqueue.nchanges = 0;
    io->Kqueue.nchanges_max = LISTINC;
    io->Kqueue.changelist = Xcalloc(io->Kqueue.nchanges_max, sizeof(struct kevent));
    io->Kqueue.nevents_max = LISTINC;
    io->Kqueue.eventlist = Xcalloc(io->Kqueue.nevents_max, sizeof(struct kevent));
    if (!timeout_immediately)
	timeout_immediately = calloc(1, sizeof(struct timespec));
}

static int kqueue_io_poll(struct io_context *io, int poll_timeout, int *cax)
{
    int count, res;
    struct timespec timeout;

    Debug((DEBUG_PROC, "io_poll (%p)\n", io));

    *cax = 0;

    timeout.tv_sec = poll_timeout / 1000;
    timeout.tv_nsec = 1000000 * (poll_timeout - 1000 * timeout.tv_sec);
    Debug((DEBUG_PROC, "nchanges is %d\n", io->Kqueue.nchanges));
    res = kevent(io->Kqueue.fd, io->Kqueue.changelist,
		 io->Kqueue.nchanges, io->Kqueue.eventlist, io->Kqueue.nevents_max, poll_timeout > -1 ? &timeout : NULL);
    io->Kqueue.nchanges = 0;

    gettimeofday(&io_now, NULL);

    for (count = 0; count < res; count++) {
	struct kevent *k = &io->Kqueue.eventlist[count];
	if (!(k->flags & EV_ERROR && k->data == EBADF)) {
	    int pos, cur = (int) k->ident;

	    if (io->rcache_map[cur] < 0) {
		io->rcache[*cax].events = 0;
		io->rcache[*cax].fd = cur;
		io->rcache_map[cur] = (*cax)++;
	    }

	    pos = io->rcache_map[cur];

	    if (k->filter == EVFILT_READ)
		io->rcache[pos].events |= POLLIN;
	    if (k->flags & EV_EOF)
		io->rcache[pos].events |= POLLHUP;
	    if (k->flags & EV_ERROR)
		io->rcache[pos].events |= POLLERR;
	    if (k->filter == EVFILT_WRITE)
		io->rcache[pos].events |= POLLOUT;
	}
    }

    return res;
}

static void kqueue_io_unregister(struct io_context *io, int fd)
{
    kqueue_io_clr_i(io, fd);
    kqueue_io_clr_o(io, fd);
    kqueue_flush(io);
}

static void kqueue_io_close(struct io_context *io, int fd)
{
    int i, j;

    for (i = 0, j = 0; i < io->Kqueue.nchanges; i++) {
	if ((int) io->Kqueue.changelist[i].ident == fd)
	    continue;
	if (i != j)
	    io->Kqueue.changelist[j] = io->Kqueue.changelist[i];
	j++;
    }
    io->Kqueue.nchanges = j;
}


static void kqueue_io_register(struct io_context *io, int fd)
{
    Debug((DEBUG_PROC, " io_register %d\n", fd));

    if (fd >= io->nfds_max)
	io_resize(io, fd);
}

static void kqueue_io_destroy(struct io_context *io)
{
    free(io->Kqueue.changelist);
    free(io->Kqueue.eventlist);
    close(io->Kqueue.fd);
}
#endif

#ifdef WITH_PORT
static void port_io_close(struct io_context *io, int fd)
{
    if (io->Port.changemap[fd] > -1) {
	io->Port.changelist[io->Port.changemap[fd]] = -1;
	io->Port.changemap[fd] = -1;
	io->Port.nchanges--;
    }
}

static void port_addchange(struct io_context *io, int fd)
{
    if (io->Port.changemap[fd] < 0 || io->Port.changemap[fd] >= io->Port.nchanges || io->Port.changelist[io->Port.changemap[fd]] != fd) {
	io->Port.changemap[fd] = io->Port.nchanges;
	io->Port.changelist[io->Port.nchanges++] = fd;
    }
}

static void port_io_set_i(struct io_context *io, int fd)
{
    if (!io->handler[fd].want_read) {
	io->handler[fd].want_read = 1;
	port_addchange(io, fd);
    }
}

static void port_io_clr_i(struct io_context *io, int fd)
{
    if (io->handler[fd].want_read) {
	io->handler[fd].want_read = 0;
	port_addchange(io, fd);
    }
}

static void port_io_set_o(struct io_context *io, int fd)
{
    if (!io->handler[fd].want_write) {
	io->handler[fd].want_write = 1;
	port_addchange(io, fd);
    }
}

static void port_io_clr_o(struct io_context *io, int fd)
{
    if (io->handler[fd].want_write) {
	io->handler[fd].want_write = 0;
	port_addchange(io, fd);
    }
}

static void port_io_init(struct io_context *io)
{
    int flags, i;

    io->Port.nevents_max = LISTINC;
    io->Port.eventlist = Xcalloc(io->Port.nevents_max, sizeof(port_event_t));

    io->Port.fd = port_create();
    flags = fcntl(io->Port.fd, F_GETFD, 0) | FD_CLOEXEC;
    fcntl(io->Port.fd, F_SETFD, flags);

    io->Port.changelist = Xcalloc(io->nfds_max, sizeof(int));
    io->Port.changemap = Xcalloc(io->nfds_max, sizeof(int));
    for (i = 0; i < io->Port.nevents_max; i++) {
	io->Port.changelist[i] = -1;
	io->Port.changemap[i] = -1;
    }
}

static int port_io_poll(struct io_context *io, int poll_timeout, int *cax)
{
    uint_t count;
    uint_t nevents = 1;
    struct timespec timeout;

    *cax = 0;

    Debug((DEBUG_PROC, "io_poll (%p)\n", io));

    for (count = 0; count < (uint_t) io->Port.nchanges; count++) {
	int fd = io->Port.changelist[count];
	if (fd > -1 && io->Port.changemap[fd] == (int) count) {
	    if (0 > port_associate(io->Port.fd, PORT_SOURCE_FD, fd,
				   (io->handler[fd].want_read ? POLLIN : 0) | (io->handler[fd].want_write ? POLLOUT : 0), &io->handler[fd]))
		logerr("port_associate (%s:%d)", __FILE__, __LINE__);

	    io->Port.changemap[fd] = -1;
	}
    }
    io->Port.nchanges = 0;

    timeout.tv_sec = poll_timeout / 1000;
    timeout.tv_nsec = 1000000 * (poll_timeout - 1000 * timeout.tv_sec);

    if (-1 == port_getn(io->Port.fd, io->Port.eventlist, io->Port.nevents_max, &nevents, poll_timeout < 0 ? NULL : &timeout)) {
	if (errno != ETIME) {
	    logerr("port_getn (errno = %d)", errno);
	    abort();
	}
	nevents = 0;
    }

    gettimeofday(&io_now, NULL);

    for (count = 0; count < nevents; count++) {
	int pos, cur = io->Port.eventlist[count].portev_object;

	if (io->rcache_map[cur] < 0) {
	    io->rcache[*cax].events = 0;
	    io->rcache[*cax].fd = cur;
	    io->rcache_map[cur] = (*cax)++;
	}

	pos = io->rcache_map[cur];

	io->rcache[pos].events = io->Port.eventlist[count].portev_events;
    }

    return (int) nevents;
}

static void port_io_poll_finish(struct io_context *io, int nevents)
{
    int count;
    for (count = 0; count < nevents; count++) {
	int cur = io->Port.eventlist[count].portev_object;
	if (io->handler[cur].want_read || io->handler[cur].want_write)
	    port_addchange(io, cur);
    }
}

static void port_io_unregister(struct io_context *io, int fd)
{
    port_dissociate(io->Port.fd, PORT_SOURCE_FD, fd);
    io->Port.changemap[fd] = -1;
}

static void port_io_register(struct io_context *io, int fd)
{
    Debug((DEBUG_PROC, " io_register %d\n", fd));

    if (fd >= io->nfds_max) {
	int i;
	int omax = io->nfds_max;

	io->Port.changelist = Xrealloc(io->Port.changelist, io->nfds_max * sizeof(int));
	io->Port.changemap = Xrealloc(io->Port.changemap, io->nfds_max * sizeof(int));

	for (i = omax; i < io->Port.nevents_max; i++) {
	    io->Port.changelist[i] = -1;
	    io->Port.changemap[i] = -1;
	}
	io_resize(io, fd);
    }
}

static void port_io_destroy(struct io_context *io)
{
    free(io->Port.eventlist);
    free(io->Port.changelist);
    free(io->Port.changemap);
    close(io->Port.fd);
}
#endif

static void insert_isc(rb_tree_t * t, struct io_sched *isc)
{
    while (!RB_insert(t, isc)) {
	isc->time_when.tv_usec++;
	if (isc->time_when.tv_usec > 1000000)
	    isc->time_when.tv_usec -= 1000000, isc->time_when.tv_sec++;
	isc->time_real.tv_sec = isc->time_when.tv_sec;
	isc->time_real.tv_usec = isc->time_when.tv_usec;
    }
}

void io_sched_add(struct io_context *io, void *data, void *proc, time_t tv_sec, suseconds_t tv_usec)
{
    rb_node_t *rbn;
    struct io_event *ioe = Xcalloc(1, sizeof(struct io_event));
    struct io_sched *isc, is;

    Debug((DEBUG_PROC, "io_sched_add %p %ld.%ld\n", data, (long) tv_sec, (long) tv_usec));

    gettimeofday(&io_now, NULL);

    is.data = data;
    rbn = RB_search(io->events_by_data, &is);

    ioe->proc = proc;
    ioe->time_wait.tv_sec = tv_sec;
    ioe->time_wait.tv_usec = tv_usec;

    if (rbn) {
	isc = RB_payload(rbn, struct io_sched *);
	ioe->next = isc->event;
	RB_search_and_delete(io->events_by_time, isc);
    } else {
	isc = Xcalloc(1, sizeof(struct io_sched));
	isc->data = data;
	RB_insert(io->events_by_data, isc);
    }
    isc->event = ioe;
    isc->time_when.tv_sec = io_now.tv_sec + ioe->time_wait.tv_sec;
    isc->time_when.tv_usec = io_now.tv_usec + ioe->time_wait.tv_usec;
    if (isc->time_when.tv_usec > 1000000)
	isc->time_when.tv_usec -= 1000000, isc->time_when.tv_sec++;
    isc->time_real.tv_sec = isc->time_when.tv_sec;
    isc->time_real.tv_usec = isc->time_when.tv_usec;
    insert_isc(io->events_by_time, isc);
}

void io_sched_app(struct io_context *io, void *data, void *proc, time_t tv_sec, suseconds_t tv_usec)
{
    rb_node_t *rbn;
    struct io_event *ioe = Xcalloc(1, sizeof(struct io_event));
    struct io_sched is;

    DebugIn(DEBUG_PROC);

    is.data = data;
    rbn = RB_search(io->events_by_data, &is);

    ioe->proc = proc;
    ioe->time_wait.tv_sec = tv_sec;
    ioe->time_wait.tv_usec = tv_usec;

    if (rbn) {
	struct io_event *i = RB_payload(rbn, struct io_sched *)->event;
	while (i->next)
	    i = i->next;
	i->next = ioe;
    } else {
	struct io_sched *isc;
	isc = Xcalloc(1, sizeof(struct io_sched));
	isc->data = data;
	isc->event = ioe;
	isc->time_when.tv_sec = io_now.tv_sec + ioe->time_wait.tv_sec;
	isc->time_when.tv_usec = io_now.tv_usec + ioe->time_wait.tv_usec;
	if (isc->time_when.tv_usec > 1000000)
	    isc->time_when.tv_usec -= 1000000, isc->time_when.tv_sec++;
	isc->time_real.tv_sec = isc->time_when.tv_sec;
	isc->time_real.tv_usec = isc->time_when.tv_usec;
	RB_insert(io->events_by_data, isc);
	insert_isc(io->events_by_time, isc);
    }

    DebugOut(DEBUG_PROC);
}

void *io_sched_pop(struct io_context *io, void *data)
{
    rb_node_t *rbn;
    struct io_sched is;
    void *result = NULL;

    DebugIn(DEBUG_PROC);

    is.data = data;
    rbn = RB_search(io->events_by_data, &is);
    if (rbn) {
	struct io_sched *isc = RB_payload(rbn, struct io_sched *);
	struct io_event *i = isc->event;

	isc->event = i->next;
	free(i);
	RB_search_and_delete(io->events_by_time, isc);
	if (isc->event) {
	    isc->time_when.tv_sec = io_now.tv_sec + isc->event->time_wait.tv_sec;
	    isc->time_when.tv_usec = io_now.tv_usec + isc->event->time_wait.tv_usec;
	    if (isc->time_when.tv_usec > 1000000)
		isc->time_when.tv_usec -= 1000000, isc->time_when.tv_sec++;
	    isc->time_real.tv_sec = isc->time_when.tv_sec;
	    isc->time_real.tv_usec = isc->time_when.tv_usec;
	    insert_isc(io->events_by_time, isc);
	    result = isc->event->proc;
	} else {
	    RB_delete(io->events_by_data, rbn);
	    free(isc);
	}
    }
    DebugOut(DEBUG_PROC);
    return result;
}

void io_sched_drop(struct io_context *io, void *data)
{
    rb_node_t *rbn;
    struct io_sched is;

    DebugIn(DEBUG_PROC);

    is.data = data;
    rbn = RB_search(io->events_by_data, &is);
    if (rbn) {
	struct io_sched *isc = RB_payload(rbn, struct io_sched *);
	struct io_event *i = isc->event;

	isc->event = i->next;
	free(i);
	RB_search_and_delete(io->events_by_time, isc);
	while (isc->event) {
	    i = isc->event;
	    isc->event = i->next;
	    free(i);
	}
	RB_delete(io->events_by_data, rbn);
	free(isc);
    }
    DebugOut(DEBUG_PROC);
}

int io_sched_del(struct io_context *io, void *data, void *proc)
{
    int result = 0;
    struct io_sched is;
    rb_node_t *rbn;

    DebugIn(DEBUG_PROC);

    is.data = data;
    rbn = RB_search(io->events_by_data, &is);
    if (rbn) {
	struct io_sched *isc = RB_payload(rbn, struct io_sched *);
	struct io_event *i = isc->event;
	if (i) {
	    if (i->proc == proc)
		io_sched_pop(io, data), result = -1;
	    else {
		struct io_event *next;
		while (i->next)
		    if (i->next->proc == proc) {
			next = i->next;
			i->next = next->next;
			free(next);
			result = -1;
		    } else
			i = i->next;
	    }
	}
    }
    DebugOut(DEBUG_PROC);
    return result;
}

int io_sched_renew_proc(struct io_context *io, void *data, void *proc)
{
    struct io_sched is;
    rb_node_t *rbn;
    Debug((DEBUG_PROC, "io_sched_renew_proc %p\n", data));
    is.data = data;
    rbn = RB_search(io->events_by_data, &is);
    if (rbn) {
	struct io_sched *isc = RB_payload(rbn, struct io_sched *);
	if (isc && isc->event && (!proc || isc->event->proc == proc)) {
	    isc->time_real.tv_sec = io_now.tv_sec + isc->event->time_wait.tv_sec;
	    isc->time_real.tv_usec = io_now.tv_usec + isc->event->time_wait.tv_usec;
	    if (isc->time_real.tv_usec > 1000000)
		isc->time_real.tv_usec -= 1000000, isc->time_real.tv_sec++;
	    Debug((DEBUG_PROC, "to be fired at %.8lx:%.8lx\n", (long) (isc->time_real.tv_sec), (long) (isc->time_real.tv_usec)));
	    return 0;
	}
    }
    return -1;
}

void *io_sched_peek(struct io_context *io, void *data)
{
    struct io_event *ioe;
    rb_node_t *rbn;
    struct io_sched is;
    is.data = data;
    rbn = RB_search(io->events_by_data, &is);
    if (rbn && (ioe = RB_payload(rbn, struct io_sched *)->event))
	 return (void *) (ioe->proc);
    return NULL;
}

struct timeval *io_sched_peek_time(struct io_context *io, void *data)
{
    struct io_sched *ios;
    rb_node_t *rbn;
    struct io_sched is;
    is.data = data;
    rbn = RB_search(io->events_by_data, &is);
    if (rbn && (ios = RB_payload(rbn, struct io_sched *))->event)
	 return &ios->time_real;
    return NULL;
}

static void io_reschedule(struct io_context *io)
{
    rb_node_t *rbn, *rbnext;
    struct io_sched *ios;

    for (rbn = RB_first(io->events_by_time);
	 rbn &&
	 ((ios =
	   RB_payload(rbn,
		      struct io_sched *))->time_when.tv_sec < io_now.tv_sec
	  || (ios->time_when.tv_sec == io_now.tv_sec && ios->time_when.tv_usec <= io_now.tv_usec)); rbn = rbnext) {
	rbnext = RB_next(rbn);
	if (ios->time_when.tv_sec != ios->time_real.tv_sec || ios->time_when.tv_usec != ios->time_real.tv_usec) {
	    RB_delete(io->events_by_time, rbn);
	    ios->time_when.tv_sec = ios->time_real.tv_sec;
	    ios->time_when.tv_usec = ios->time_real.tv_usec;
	    insert_isc(io->events_by_time, ios);
	    Debug((DEBUG_PROC, " rescheduled at %.8lx:%.8lx (%lds)\n",
		   (long) (ios->time_when.tv_sec), (long) (ios->time_when.tv_usec), (long) (ios->time_when.tv_sec) - (long) io_now.tv_sec));
	}
    }
}

int io_sched_exec(struct io_context *io)
{
    rb_node_t *rbn, *rbnext;
    int poll_timeout = -1;
    struct io_sched *ios;

    Debug((DEBUG_PROC, "io_sched_exec (%p)\n", io));

    io_reschedule(io);

    for (rbn = RB_first(io->events_by_time);
	 rbn && (ios = RB_payload(rbn, struct io_sched *)) && (ios->time_when.tv_sec < io_now.tv_sec
							       || (ios->time_when.tv_sec == io_now.tv_sec && ios->time_when.tv_usec <= io_now.tv_usec));
	 rbn = rbnext) {
	rbnext = RB_next(rbn);
	Debug((DEBUG_PROC, " executing ...\n"));
	if (ios->event->proc)
	    ((void (*)(void *, int)) (ios->event->proc)) (ios->data, -1);
	Debug((DEBUG_PROC, "... done.\n"));
    }

    io_reschedule(io);

    rbn = RB_first(io->events_by_time);
    if (rbn) {
	ios = RB_payload(rbn, struct io_sched *);
	if (ios)
	    poll_timeout = 1 + (int) ((ios->time_when.tv_sec - io_now.tv_sec) * 1000) + (int) ((ios->time_when.tv_usec - io_now.tv_usec) / 1000);

	Debug((DEBUG_PROC, "poll_timeout = %dms\n", poll_timeout));
    }

    return poll_timeout;
}

void io_main(struct io_context *io)
{
    Debug((DEBUG_PROC, "io_main (%p)\n", io));
    do {
	gettimeofday(&io_now, NULL);
	io_poll(io, io_sched_exec(io));
    }
    while (1);
}

struct io_context *io_init()
{
    static int once = 0;
    void (*mech_io_init)(struct io_context *);
    int mode = 0
#ifdef WITH_POLL
	| IO_MODE_poll
#endif
#ifdef WITH_EPOLL
	| IO_MODE_epoll
#endif
#ifdef WITH_DEVPOLL
	| IO_MODE_devpoll
#endif
#ifdef WITH_KQUEUE
	| IO_MODE_kqueue
#endif
#ifdef WITH_SELECT
	| IO_MODE_select
#endif
#ifdef WITH_PORT
	| IO_MODE_port
#endif
	;
    char *mech, *e;
    int i;
    struct rlimit rlim;
    struct io_context *io = Xcalloc(1, sizeof(struct io_context));

    Debug((DEBUG_PROC, "io_init\n"));

    if (getrlimit(RLIMIT_NOFILE, &rlim)) {
	logerr("getrlimit");
	exit(EX_SOFTWARE);
    }

    if ((e = getenv("IO_POLL_MECHANISM")))
	mode &= atoi(e);

    mech_io_poll_finish = NULL;
    mech_io_close = NULL;

#define EVENT_MECHANISM_DEFUNCT "%s event mechanism is unavailable"

#ifdef WITH_KQUEUE
    if (mode & IO_MODE_kqueue) {
	int fd = kqueue();
	mech = "kqueue";
	if (fd > -1) {
	    close(fd);
	    mech_io_poll = kqueue_io_poll;
	    mech_io_set_i = kqueue_io_set_i;
	    mech_io_set_o = kqueue_io_set_o;
	    mech_io_clr_i = kqueue_io_clr_i;
	    mech_io_clr_o = kqueue_io_clr_o;
	    mech_io_register = kqueue_io_register;
	    mech_io_unregister = kqueue_io_unregister;
	    mech_io_destroy = kqueue_io_destroy;
	    mech_io_init = kqueue_io_init;
	    mech_io_close = kqueue_io_close;
	    goto gotit;
	}
	logerr(EVENT_MECHANISM_DEFUNCT, mech);
    }
#endif

#ifdef WITH_EPOLL
    if (mode & IO_MODE_epoll) {
	int fd = epoll_create(1);
	mech = "epoll";
	if (fd > -1) {
	    close(fd);
	    mech_io_poll = epoll_io_poll;
	    mech_io_set_i = epoll_io_set_i;
	    mech_io_set_o = epoll_io_set_o;
	    mech_io_clr_i = epoll_io_clr_i;
	    mech_io_clr_o = epoll_io_clr_o;
	    mech_io_register = epoll_io_register;
	    mech_io_unregister = epoll_io_unregister;
	    mech_io_destroy = epoll_io_destroy;
	    mech_io_init = epoll_io_init;
	    mech_io_close = epoll_io_close;
	    goto gotit;
	}
	logerr(EVENT_MECHANISM_DEFUNCT, mech);
    }
#endif

#ifdef WITH_POLL
    if (mode & IO_MODE_poll) {
	mech = "poll";
	mech_io_poll = poll_io_poll;
	mech_io_set_i = poll_io_set_i;
	mech_io_set_o = poll_io_set_o;
	mech_io_clr_i = poll_io_clr_i;
	mech_io_clr_o = poll_io_clr_o;
	mech_io_register = poll_io_register;
	mech_io_unregister = poll_io_unregister;
	mech_io_destroy = poll_io_destroy;
	mech_io_init = poll_io_init;
	goto gotit;
    }
#endif

#ifdef WITH_DEVPOLL
// Solaris /dev/poll may or may not work correctly. Placed *after* standard
// poll on purpose, so it won't be used unless specified.
    if (mode & IO_MODE_devpoll) {
	int fd = open("/dev/poll", O_RDWR);
	mech = "/dev/poll";
	if (fd > -1) {
	    close(fd);
	    mech_io_poll = devpoll_io_poll;
	    mech_io_set_i = devpoll_io_set_i;
	    mech_io_set_o = devpoll_io_set_o;
	    mech_io_clr_i = devpoll_io_clr_i;
	    mech_io_clr_o = devpoll_io_clr_o;
	    mech_io_register = devpoll_io_register;
	    mech_io_unregister = devpoll_io_unregister;
	    mech_io_destroy = devpoll_io_destroy;
	    mech_io_init = devpoll_io_init;
	    mech_io_close = devpoll_io_close;
	    if (rlim.rlim_max > OPEN_MAX)
		rlim.rlim_max = OPEN_MAX;
	    goto gotit;
	}
	logerr(EVENT_MECHANISM_DEFUNCT, mech);
    }
#endif

#ifdef WITH_PORT
// Solaris port(2) may or may not work correctly. Placed *after* standard poll
// on purpose, so it won't be used unless specified.
    if (mode & IO_MODE_port) {
	int fd = port_create();
	mech = "port";
	if (fd > -1) {
	    close(fd);
	    mech_io_poll = port_io_poll;
	    mech_io_poll_finish = port_io_poll_finish;
	    mech_io_set_i = port_io_set_i;
	    mech_io_set_o = port_io_set_o;
	    mech_io_clr_i = port_io_clr_i;
	    mech_io_clr_o = port_io_clr_o;
	    mech_io_register = port_io_register;
	    mech_io_unregister = port_io_unregister;
	    mech_io_destroy = port_io_destroy;
	    mech_io_init = port_io_init;
	    mech_io_close = port_io_close;
	    goto gotit;
	}
	logerr(EVENT_MECHANISM_DEFUNCT, mech);
    }
#endif

#ifdef WITH_SELECT
// select(2) comes last and won't be used unless manually chosen.
    if (mode & IO_MODE_select) {
	mech = "select";
	mech_io_poll = select_io_poll;
	mech_io_set_i = select_io_set_i;
	mech_io_set_o = select_io_set_o;
	mech_io_clr_i = select_io_clr_i;
	mech_io_clr_o = select_io_clr_o;
	mech_io_register = select_io_register;
	mech_io_unregister = select_io_unregister;
	mech_io_destroy = select_io_destroy;
	mech_io_init = select_io_init;
	if (rlim.rlim_max > FD_SETSIZE)
	    rlim.rlim_max = FD_SETSIZE;
	goto gotit;
    }
#endif

    logmsg("no working event notification mechanism found");
    abort();

  gotit:
    if (!once) {
	logmsg("%s event notification mechanism is being used", mech);
	once++;
    }

    rlim.rlim_cur = rlim.rlim_max;
    setrlimit(RLIMIT_NOFILE, &rlim);
    getrlimit(RLIMIT_NOFILE, &rlim);
    io->nfds_limit = (int) rlim.rlim_cur;
    io->nfds_max = MINIMUM(io->nfds_limit, ARRAYINC);
    io->handler = Xcalloc(io->nfds_max, sizeof(struct io_handler));

    mech_io_init(io);

    io->events_by_time = RB_tree_new(cmp_tv, NULL);
    io->events_by_data = RB_tree_new(cmp_data, NULL);
    io->io_invalid_i = (void *) io_invalid_i;
    io->io_invalid_o = (void *) io_invalid_o;
    io->io_invalid_e = (void *) io_invalid_e;
    io->io_invalid_h = (void *) io_invalid_h;

    io->rcache_map = Xcalloc(io->nfds_max, sizeof(int));
    for (i = 0; i < io->nfds_max; i++)
	io->rcache_map[i] = -1;
    io->rcache = Xcalloc(io->nfds_max, sizeof(struct event_cache));

    gettimeofday(&io_now, NULL);

    return io;
}

static void io_resize(struct io_context *io, int fd)
{
    int i, omax = io->nfds_max;

    if (io->nfds_limit == io->nfds_max) {
	logmsg("ABORT: Can't handle file descriptor %d at %s:%d", fd, __func__, __LINE__);
	abort();
    }

    io->nfds_max = MINIMUM(io->nfds_limit, MAXIMUM(fd + 1, io->nfds_max + ARRAYINC));

    if (io->nfds_max <= fd) {
	logmsg("ABORT: Can't handle file descriptor %d at %s:%d", fd, __func__, __LINE__);
	abort();
    }

    io->handler = Xrealloc(io->handler, io->nfds_max * sizeof(struct io_handler));

    memset(&io->handler[omax], 0, (io->nfds_max - omax) * sizeof(struct io_handler));

    io->rcache_map = Xrealloc(io->rcache_map, io->nfds_max * sizeof(int));

    for (i = omax; i < io->nfds_max; i++)
	io->rcache_map[i] = -1;

    io->rcache = Xrealloc(io->rcache, io->nfds_max * sizeof(struct event_cache));
}

void *io_get_cb_i(struct io_context *io, int fd)
{
    return io->handler[fd].i;
}

void *io_get_cb_o(struct io_context *io, int fd)
{
    return io->handler[fd].o;
}

void *io_get_cb_h(struct io_context *io, int fd)
{
    return io->handler[fd].h;
}

void *io_get_cb_e(struct io_context *io, int fd)
{
    return io->handler[fd].e;
}

void *io_get_ctx(struct io_context *io, int fd)
{
    return io->handler[fd].data;
}

int io_want_read(struct io_context *io, int fd)
{
    return io->handler[fd].want_read_app;
}

int io_want_write(struct io_context *io, int fd)
{
    return io->handler[fd].want_write_app;
}

void io_set_cb_i(struct io_context *io, int fd, void *f)
{
    io->handler[fd].i_app = f;
    if (!io->handler[fd].reneg)
	io->handler[fd].i = f;
}

void io_set_cb_o(struct io_context *io, int fd, void *f)
{
    io->handler[fd].o_app = f;
    if (!io->handler[fd].reneg)
	io->handler[fd].o = f;
}

void io_set_cb_e(struct io_context *io, int fd, void *f)
{
    io->handler[fd].e = f;
}

void io_set_cb_h(struct io_context *io, int fd, void *f)
{
    io->handler[fd].h = f;
}

void io_set_cb_inv_i(struct io_context *io, void *f)
{
    io->io_invalid_i = f;
}

void io_set_cb_inv_o(struct io_context *io, void *f)
{
    io->io_invalid_o = f;
}

void io_set_cb_inv_h(struct io_context *io, void *f)
{
    io->io_invalid_h = f;
}

void io_set_cb_inv_e(struct io_context *io, void *f)
{
    io->io_invalid_e = f;
}

void io_clr_cb_i(struct io_context *io, int fd)
{
    io->handler[fd].want_read_app = 0;
#if defined(WITH_SSL) || defined(WITH_TLS)
    if (io->handler[fd].want_read_ssl)
	return;
#endif
    io->handler[fd].want_read = 0;
    io_set_cb_i(io, fd, io->io_invalid_i);
    io_clr_i(io, fd);
}

void io_clr_cb_o(struct io_context *io, int fd)
{
    io->handler[fd].want_write_app = 0;
#if defined(WITH_SSL) || defined(WITH_TLS)
    if (io->handler[fd].want_write_ssl)
	return;
#endif
    io->handler[fd].want_write = 0;
    io_set_cb_o(io, fd, io->io_invalid_o);
    io_clr_o(io, fd);
}

void io_clr_cb_e(struct io_context *io, int fd)
{
    io_set_cb_e(io, fd, io->io_invalid_e);
}

void io_clr_cb_h(struct io_context *io, int fd)
{
    io_set_cb_h(io, fd, io->io_invalid_h);
}

#ifdef WITH_TLS
static ssize_t io_TLS_rw(struct tls *ssl __attribute__((unused)), struct io_context *io, int fd, void *cb, int res)
{
    DebugIn(DEBUG_PROC | DEBUG_NET);
    if (io->handler[fd].reneg && res != TLS_WANT_POLLIN && res != TLS_WANT_POLLOUT) {
	io->handler[fd].reneg = 0;
	io_SSL_clr_i(io, fd);
	io_SSL_clr_o(io, fd);
	io->handler[fd].i = io->handler[fd].i_app;
	io->handler[fd].o = io->handler[fd].o_app;
    } else if (res < 0 && !io->handler[fd].reneg && (res == TLS_WANT_POLLIN || res == TLS_WANT_POLLOUT)) {
	Debug((DEBUG_PROC | DEBUG_NET, "TLS shutdown or renegotiation initiated " "(res = %d, error = %s)\n", res, tls_error(ssl)));
	io->handler[fd].reneg = 1;
	io->handler[fd].i = cb;
	io->handler[fd].o = cb;

	if (res == TLS_WANT_POLLIN) {
	    io_SSL_clr_o(io, fd);
	    io_SSL_set_i(io, fd);
	} else {
	    io_SSL_clr_i(io, fd);
	    io_SSL_set_o(io, fd);
	}

	errno = EAGAIN;
    }
    DebugOut(DEBUG_PROC | DEBUG_NET);
    return res;
}

ssize_t io_TLS_read(struct tls *ssl, void *buf, size_t num, struct io_context *io, int fd, void *cb)
{
    return io_TLS_rw(ssl, io, fd, cb, tls_read(ssl, buf, (int) num));
}

ssize_t io_TLS_write(struct tls *ssl, void *buf, size_t num, struct io_context *io, int fd, void *cb)
{
    return io_TLS_rw(ssl, io, fd, cb, tls_write(ssl, buf, (int) num));
}

int io_TLS_shutdown(struct tls *ssl, struct io_context *io, int fd, void *cb)
{
    Debug((DEBUG_PROC | DEBUG_NET, "%s\n", __func__));
    int res = tls_close(ssl);	// check res, might be TLS_WANT_POLL...
    Debug((DEBUG_PROC | DEBUG_NET, "SSL_shutdown = %d\n", res));
    return (int) io_TLS_rw(ssl, io, fd, cb, res);
}
#endif
#ifdef WITH_SSL
#include <openssl/ssl.h>

static ssize_t io_SSL_rw(SSL * ssl __attribute__((unused)), struct io_context *io, int fd, void *cb, int res)
{
    DebugIn(DEBUG_PROC | DEBUG_NET);
    if (io->handler[fd].reneg && !SSL_want_read(ssl)
	&& !SSL_want_write(ssl)) {
	io->handler[fd].reneg = 0;
	io_SSL_clr_i(io, fd);
	io_SSL_clr_o(io, fd);
	io->handler[fd].i = io->handler[fd].i_app;
	io->handler[fd].o = io->handler[fd].o_app;
    } else if (res < 0 && !io->handler[fd].reneg && (SSL_want_read(ssl) || SSL_want_write(ssl))) {
	Debug((DEBUG_PROC | DEBUG_NET, "TLS shutdown or renegotiation initiated " "(res = %d, error = %d)\n", res, SSL_get_error(ssl, res)));
	io->handler[fd].reneg = 1;
	io->handler[fd].i = cb;
	io->handler[fd].o = cb;

	if (SSL_want_read(ssl)) {
	    io_SSL_clr_o(io, fd);
	    io_SSL_set_i(io, fd);
	} else {
	    io_SSL_clr_i(io, fd);
	    io_SSL_set_o(io, fd);
	}

	errno = EAGAIN;
    }
    DebugOut(DEBUG_PROC | DEBUG_NET);
    return res;
}

ssize_t io_SSL_read(SSL * ssl, void *buf, size_t num, struct io_context *io, int fd, void *cb)
{
    return io_SSL_rw(ssl, io, fd, cb, SSL_read(ssl, buf, (int) num));
}

ssize_t io_SSL_write(SSL * ssl, void *buf, size_t num, struct io_context *io, int fd, void *cb)
{
    return io_SSL_rw(ssl, io, fd, cb, SSL_write(ssl, buf, (int) num));
}

int io_SSL_shutdown(SSL * ssl, struct io_context *io, int fd, void *cb)
{
    Debug((DEBUG_PROC | DEBUG_NET, "%s\n", __func__));
    int res = SSL_shutdown(ssl);
    Debug((DEBUG_PROC | DEBUG_NET, "SSL_shutdown = %d\n", res));
    if (res < 1)
	res = -1;
    return (int) io_SSL_rw(ssl, io, fd, cb, res);
}
#endif				/* WITH_SSL */

void io_clone(struct io_context *io, int to, int from)
{
    Debug((DEBUG_PROC, "io_clone (%d, %d)\n", to, from));

    io->handler[to] = io->handler[from];

    if (io->handler[to].want_read) {
	io->handler[to].want_read = 0;
	mech_io_set_i(io, to);
    }
    if (io->handler[to].want_write) {
	io->handler[to].want_write = 0;
	mech_io_set_o(io, to);
    }
}

int io_get_nfds_limit(struct io_context *io)
{
    return io ? io->nfds_limit : 0;
}
