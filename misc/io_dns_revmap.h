/*
 * io_dns_revmap.h
 * (C)2002-2011 Marc Huber <Marc.Huber@web.de>
 *
 * All rights reserved.
 */

#ifndef _IO_DNS_REVMAP_H_
#define _IO_DNS_REVMAP_H_

#include "misc/io_sched.h"
#include "misc/net.h"

struct io_dns_ctx;
struct io_dns_ctx *io_dns_init(struct io_context *);
void io_dns_cancel(struct io_dns_ctx *, void *);
void io_dns_destroy(struct io_dns_ctx *);
void io_dns_add(struct io_dns_ctx *, sockaddr_union *, void *, void *);
void io_dns_add_addr(struct io_dns_ctx *, struct in6_addr *, void *, void *);
int io_dns_set_servers(struct io_dns_ctx *, char *);
void io_dns_set_vrf(struct io_dns_ctx *, char *);
#endif				/* _IO_DNS_REVMAP_H_ */
