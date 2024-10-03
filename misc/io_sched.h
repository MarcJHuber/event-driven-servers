/*
 * io_sched.h
 * (C)2001-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id: io_sched.h,v 1.11 2012/10/06 07:41:01 marc Exp marc $
 *
 */

#ifndef __IO_SCHED_H__
#define __IO_SCHED_H__

#include "misc/sysconf.h"

#ifdef WITH_TLS
#include <tls.h>
#endif

struct io_context;
typedef struct io_context io_context_t;

#ifdef __IO_SCHED_C__
#define EXT
#else
#define EXT extern
#endif
EXT struct timeval io_now;
#undef EXT

void io_register(io_context_t *, int, void *);
void *io_unregister(io_context_t *, int);
int io_poll(io_context_t *, int);
void io_set_i(io_context_t *, int);
void io_set_o(io_context_t *, int);
void io_clr_i(io_context_t *, int);
void io_clr_o(io_context_t *, int);
void io_main(io_context_t *) __attribute__((noreturn));
void io_sched_add(io_context_t *, void *, void *, time_t, suseconds_t);
void io_sched_app(io_context_t *, void *, void *, time_t, suseconds_t);
int io_sched_del(io_context_t *, void *, void *);
int io_sched_renew_proc(io_context_t *, void *, void *);
#define io_sched_renew(A,B) io_sched_renew_proc(A,B,NULL)
int io_sched_exec(io_context_t *);
io_context_t *io_init();
io_context_t *io_destroy(io_context_t *, void (*)(void *));
struct timeval *io_sched_peek_time(io_context_t * io, void *data);
void *io_sched_pop(io_context_t *, void *);
void *io_sched_peek(io_context_t *, void *data);
void *io_get_cb_i(io_context_t *, int);
void *io_get_cb_e(io_context_t *, int);
void *io_get_cb_o(io_context_t *, int);
void *io_get_cb_h(io_context_t *, int);
void *io_get_ctx(io_context_t *, int);
void io_set_cb_i(io_context_t *, int, void *);
void io_set_cb_o(io_context_t *, int, void *);
void io_set_cb_e(io_context_t *, int, void *);
void io_set_cb_h(io_context_t *, int, void *);
void io_set_cb_inv_i(io_context_t *, void *);
void io_set_cb_inv_o(io_context_t *, void *);
void io_set_cb_inv_h(io_context_t *, void *);
void io_set_cb_inv_e(io_context_t *, void *);
void io_clr_cb_o(io_context_t *, int);
void io_clr_cb_e(io_context_t *, int);
void io_clr_cb_h(io_context_t *, int);
void io_clr_cb_i(io_context_t *, int);
int io_want_read(io_context_t *, int);
int io_want_write(io_context_t *, int);
int io_is_invalid_i(io_context_t *, int);
int io_is_invalid_o(io_context_t *, int);
int io_is_invalid_h(io_context_t *, int);
int io_is_invalid_e(io_context_t *, int);
int io_close(io_context_t *, int);
void io_clone(io_context_t *, int, int);
int io_get_nfds_limit(struct io_context *);

#ifdef WITH_SSL
ssize_t io_SSL_read(SSL *, void *, size_t, io_context_t *, int, void *);
ssize_t io_SSL_write(SSL *, void *, size_t, io_context_t *, int, void *);
int io_SSL_shutdown(SSL *, io_context_t *, int, void *);
#endif				/* WITH_SSL */
#ifdef WITH_TLS
ssize_t io_TLS_read(struct tls *, void *, size_t, io_context_t *, int, void *);
ssize_t io_TLS_write(struct tls *, void *, size_t, io_context_t *, int, void *);
int io_TLS_shutdown(struct tls *, io_context_t *, int, void *);
#endif				/* WITH_SSL */

#endif				/* __IO_SCHED_H__ */
