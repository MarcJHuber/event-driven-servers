/*
 * io_dns_revmap.c
 * (C) 2002-2011 Marc Huber <Marc.Huber@web.de>
 *
 */

#include <string.h>
#include "misc/sysconf.h"
#include "misc/io_dns_revmap.h"
#include "misc/rb.h"
#include "misc/net.h"
#include "misc/memops.h"

#include <lwres/lwres.h>

struct io_dns_item {
    void *app_cb;
    void *app_ctx;
    uint32_t serial;
};

struct io_dns_ctx {
    struct io_context *io;
    rb_tree_t *by_serial;
    rb_tree_t *by_app_ctx;
    lwres_context_t *ctx;
    int registered;
};

static int idi_cmp_serial(const void *v1, const void *v2)
{
    if (((struct io_dns_item *) v1)->serial < ((struct io_dns_item *) v2)->serial)
	return -1;
    if (((struct io_dns_item *) v1)->serial > ((struct io_dns_item *) v2)->serial)
	return +1;
    return 0;
}

static int idi_cmp_app_ctx(const void *v1, const void *v2)
{
    if (((struct io_dns_item *) v1)->app_ctx < ((struct io_dns_item *) v2)->app_ctx)
	return -1;
    if (((struct io_dns_item *) v1)->app_ctx > ((struct io_dns_item *) v2)->app_ctx)
	return +1;
    return 0;
}

static void free_payload(void *v)
{
    free(v);
}

static void io_dns_cb(struct io_dns_ctx *, int);

static void udp_error(void *ctx __attribute__((unused)), int cur)
{
    int sockerr;
    socklen_t sockerrlen = sizeof(sockerr);
    getsockopt(cur, SOL_SOCKET, SO_ERROR, (char *) &sockerr, &sockerrlen);
}

static void lwres_register(struct io_dns_ctx *idc)
{
    int s = lwres_context_getsocket(idc->ctx);

    if (s > -1) {
	io_register(idc->io, s, idc);
	io_set_cb_i(idc->io, s, (void *) io_dns_cb);
	io_set_cb_h(idc->io, s, (void *) udp_error);
	io_set_cb_e(idc->io, s, (void *) udp_error);
	io_clr_o(idc->io, s);
	io_set_i(idc->io, s);
	idc->registered = 1;
    }
}

struct io_dns_ctx *io_dns_init(struct io_context *io)
{
    struct io_dns_ctx *idc = Xcalloc(1, sizeof(struct io_dns_ctx));
    if (LWRES_R_SUCCESS == lwres_context_create(&idc->ctx, NULL, NULL, NULL, 0)) {
	idc->io = io;
	idc->by_serial = RB_tree_new(idi_cmp_serial, NULL);
	idc->by_app_ctx = RB_tree_new(idi_cmp_app_ctx, free_payload);
	lwres_register(idc);
    } else {
	free(idc);
	idc = NULL;
    }
    return idc;
}

void io_dns_cancel(struct io_dns_ctx *idc, void *app_ctx)
{
    struct io_dns_item i;
    rb_node_t *r;
    i.app_ctx = app_ctx;
    if ((r = RB_search(idc->by_app_ctx, &i))) {
	RB_search_and_delete(idc->by_serial, RB_payload(r, void *));
	RB_delete(idc->by_app_ctx, r);
    }
}

void io_dns_destroy(struct io_dns_ctx *idc)
{
    int sock = lwres_context_getsocket(idc->ctx);
    if (idc->registered && sock > -1)
	io_unregister(idc->io, sock);
    RB_tree_delete(idc->by_serial);
    RB_tree_delete(idc->by_app_ctx);
    lwres_context_destroy(&idc->ctx);
    free(idc);
}

void io_dns_add_addr(struct io_dns_ctx *idc, struct in6_addr *a, void *app_cb, void *app_ctx)
{
    sockaddr_union su;

    memset(&su, 0, sizeof(sockaddr_union));

#ifdef AF_INET
    if (a->s6_addr32[0] == 0 && a->s6_addr32[1] == 0 && a->s6_addr32[2] == 0x0000FFFF) {
	su.sin.sin_addr.s_addr = htonl(a->s6_addr32[3]);
	su.sa.sa_family = AF_INET;
    }
#ifdef AF_INET6
    else
#endif
#endif
#ifdef AF_INET6
    {
	v6_ntoh(&su.sin6.sin6_addr, a);
	su.sa.sa_family = AF_INET6;
    }
#endif
    io_dns_add(idc, &su, app_cb, app_ctx);
}

void io_dns_add(struct io_dns_ctx *idc, sockaddr_union * su, void *app_cb, void *app_ctx)
{
    lwres_gnbarequest_t req;
    lwres_lwpacket_t pkt;
    lwres_buffer_t b;
    uint32_t serial;

    b.base = NULL;

    req.flags = 0;
    switch (su->sa.sa_family) {
#ifdef AF_INET
    case AF_INET:
	req.addr.family = LWRES_ADDRTYPE_V4;
	req.addr.length = 4;
	memcpy(req.addr.address, &su->sin.sin_addr, 4);
	break;
#endif				/* AF_INET */
#ifdef AF_INET6
    case AF_INET6:
	req.addr.family = LWRES_ADDRTYPE_V6;
	req.addr.length = 16;
	memcpy(req.addr.address, &su->sin6.sin6_addr, 16);
#endif				/* AF_INET6 */
    }
    pkt.result = 0;
    pkt.pktflags = 0;
    pkt.serial = serial = lwres_context_nextserial(idc->ctx);
    pkt.recvlength = LWRES_RECVLENGTH;

    if (LWRES_R_SUCCESS == lwres_gnbarequest_render(idc->ctx, &req, &pkt, &b)) {
	if (LWRES_R_SUCCESS == lwres_context_send(idc->ctx, b.base, b.length)) {
	    struct io_dns_item *i = Xcalloc(1, sizeof(struct io_dns_item));
	    i->serial = serial;
	    i->app_cb = app_cb;
	    i->app_ctx = app_ctx;
	    RB_insert(idc->by_serial, i);
	    RB_insert(idc->by_app_ctx, i);

	    if (!idc->registered)
		lwres_register(idc);

	}
	free(b.base);
    }
}

static void io_dns_cb(struct io_dns_ctx *idc, int sock __attribute__((unused)))
{
    lwres_buffer_t b;
    lwres_lwpacket_t pkt;
    struct io_dns_item i;
    rb_node_t *r;
    char buffer[LWRES_RECVLENGTH];
    int rlen;
    b.base = NULL;

    if (LWRES_R_SUCCESS == lwres_context_recv(idc->ctx, buffer, LWRES_RECVLENGTH, &rlen)) {
	lwres_buffer_init(&b, buffer, rlen);
	b.used = rlen;

	if (LWRES_R_SUCCESS == lwres_lwpacket_parseheader(&b, &pkt) && LWRES_OPCODE_GETNAMEBYADDR == pkt.opcode) {
	    i.serial = pkt.serial;
	    r = RB_search(idc->by_serial, &i);
	    if (r) {
		struct io_dns_item *p = RB_payload(r, struct io_dns_item *);
		switch (pkt.result) {
		case LWRES_R_SUCCESS:{
			lwres_gnbaresponse_t *response = NULL;
			if (LWRES_R_SUCCESS == lwres_gnbaresponse_parse(idc->ctx, &b, &pkt, &response)) {
			    if (response->realnamelen > 0)
				((void (*)(void *, char *)) p->app_cb)
				    (p->app_ctx, response->realname);
			    lwres_gnbaresponse_free(idc->ctx, &response);
			}
			break;
		    }
		default:	// Failure. Tell the caller by returning a NULL pointer.
		    ((void (*)(void *, char *)) p->app_cb) (p->app_ctx, NULL);
		}
		RB_search_and_delete(idc->by_app_ctx, p);
		RB_delete(idc->by_serial, r);
	    }
	}
    }
}

#if 0
static void testcb(void *ctx __attribute__((unused)), char *hostname)
{
    fprintf(stderr, "%s\n", hostname);
    exit(0);
}

int main(int argc, char **argv)
{
    struct io_context *io = io_init();
    struct io_dns_ctx *idc;
    sockaddr_union su;

    su_pton(&su, argv[1]);

    idc = io_dns_init(io);

    io_dns_add(idc, &su, testcb, &su);
    io_main(io);
}
#endif
