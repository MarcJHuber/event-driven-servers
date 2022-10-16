/*
 * io_dns_revmap.c
 * (C) 2002-2011 Marc Huber <Marc.Huber@web.de>
 *
 */

#include <stdio.h>
#include <string.h>
#include "misc/sysconf.h"
#include "misc/io_dns_revmap.h"
#include "misc/rb.h"
#include "misc/net.h"
#include "misc/memops.h"

#ifdef WITH_ARES
#include <ares.h>
#include <ares_nameser.h>
#include <sys/uio.h>
#undef WITH_LWRES
#endif

#ifdef WITH_LWRES
#include <lwres/lwres.h>
#endif

struct io_dns_item {
    void *app_cb;
    void *app_ctx;
#ifdef WITH_ARES
    struct io_dns_ctx *idc;
#endif
#ifdef WITH_LWRES
    uint32_t serial;
#endif
};

struct io_dns_ctx {
    struct io_context *io;
#ifdef WITH_ARES
    rb_tree_t *by_addr;
#endif
#ifdef WITH_LWRES
    rb_tree_t *by_serial;
#endif
    rb_tree_t *by_app_ctx;
#ifdef WITH_ARES
    ares_channel channel;
#endif
#ifdef WITH_LWRES
    lwres_context_t *ctx;
    int registered;
#endif
};

#ifdef WITH_ARES
static int idi_cmp_addr(const void *v1, const void *v2)
{
    if (v1 < v2)
	return -1;
    if (v1 > v2)
	return +1;
    return 0;
}
#endif
#ifdef WITH_LWRES
static int idi_cmp_serial(const void *v1, const void *v2)
{
    if (((struct io_dns_item *) v1)->serial < ((struct io_dns_item *) v2)->serial)
	return -1;
    if (((struct io_dns_item *) v1)->serial > ((struct io_dns_item *) v2)->serial)
	return +1;
    return 0;
}
#endif

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

#ifdef WITH_ARES
static void io_ares_set(struct io_dns_ctx *);

static void io_ares_read(struct io_dns_ctx *idc, int sock)
{
    ares_process_fd(idc->channel, sock, ARES_SOCKET_BAD);
    io_ares_set(idc);
}

static void io_ares_write(struct io_dns_ctx *idc, int sock)
{
    ares_process_fd(idc->channel, ARES_SOCKET_BAD, sock);
    io_ares_set(idc);
}

static void io_ares_readwrite(struct io_dns_ctx *idc, int sock)
{
    ares_process_fd(idc->channel, sock, sock);
    io_ares_set(idc);
}

static void io_ares_set(struct io_dns_ctx *idc)
{
    ares_socket_t socks[ARES_GETSOCK_MAXNUM];
    int i, bits;
    for (i = 0; i < ARES_GETSOCK_MAXNUM; i++)
	socks[i] = ARES_SOCKET_BAD;
    bits = ares_getsock(idc->channel, socks, ARES_GETSOCK_MAXNUM);
    for (i = 0; i < ARES_GETSOCK_MAXNUM; i++) {
	int s = socks[i];
	if (s != ARES_SOCKET_BAD) {
	    if (ARES_GETSOCK_WRITABLE(bits, i))
		io_set_o(idc->io, s);
	    else
		io_clr_o(idc->io, s);
	    if (ARES_GETSOCK_READABLE(bits, i))
		io_set_i(idc->io, s);
	    else
		io_clr_i(idc->io, s);
	}
    }
}
#endif
#ifdef WITH_LWRES
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
#endif

static ares_socket_t asocket(int domain, int type, int protocol, void *opaque)
{
    struct io_dns_ctx *idc = (struct io_dns_ctx *) opaque;
    int fd = socket(domain, type, protocol);
    if (fd > -1) {
	io_register(idc->io, fd, idc);
	io_set_cb_i(idc->io, fd, (void *) io_ares_read);
	io_set_cb_o(idc->io, fd, (void *) io_ares_write);
	io_set_cb_h(idc->io, fd, (void *) io_ares_readwrite);
	io_set_cb_e(idc->io, fd, (void *) io_ares_readwrite);
    }
    return fd;
}

static int aclose(ares_socket_t fd, void *opaque)
{
    struct io_dns_ctx *idc = (struct io_dns_ctx *) opaque;
    int res = close(fd);
    io_unregister(idc->io, fd);
    return res;
}

static int aconnect(ares_socket_t fd, const struct sockaddr *addr, ares_socklen_t addrlen, void *opaque __attribute__((unused)))
{
    return connect(fd, addr, addrlen);
}

static ares_ssize_t arecvfrom(ares_socket_t fd, void *buf, size_t len, int flags, struct sockaddr *src_addr, ares_socklen_t * addrlen, void *opaque
			      __attribute__((unused)))
{
    return recvfrom(fd, buf, len, flags, src_addr, addrlen);
}

static ares_ssize_t asendv(ares_socket_t fd, const struct iovec *iov, int iovcnt, void *opaque __attribute__((unused)))
{
    return writev(fd, iov, iovcnt);
}

struct io_dns_ctx *io_dns_init(struct io_context *io)
{
    struct io_dns_ctx *idc = Xcalloc(1, sizeof(struct io_dns_ctx));
#ifdef WITH_ARES
    struct ares_options options;
    static struct ares_socket_functions a_socket_functions;
    int res;
    memset(&options, 0, sizeof(options));
    options.flags = ARES_FLAG_STAYOPEN;
    options.lookups = "b";
    idc->channel = calloc(1, sizeof(ares_channel));;
    memset(&idc->channel, 0, sizeof(ares_channel));
    res = ares_init_options(&idc->channel, &options, ARES_OPT_LOOKUPS);
    if (res == ARES_SUCCESS) {
	a_socket_functions.asocket = asocket;
	a_socket_functions.aclose = aclose;
	a_socket_functions.aconnect = aconnect;
	a_socket_functions.arecvfrom = arecvfrom;
	a_socket_functions.asendv = asendv;
	ares_set_socket_functions(idc->channel, &a_socket_functions, idc);
	idc->io = io;
	idc->by_addr = RB_tree_new(idi_cmp_addr, NULL);
	idc->by_app_ctx = RB_tree_new(idi_cmp_app_ctx, free_payload);
	io_ares_set(idc);
    } else {
	free(idc->channel);
	free(idc);
	idc = NULL;
    }
#endif
#ifdef WITH_LWRES
    if (LWRES_R_SUCCESS == lwres_context_create(&idc->ctx, NULL, NULL, NULL, 0)) {
	idc->io = io;
	idc->by_serial = RB_tree_new(idi_cmp_serial, NULL);
	idc->by_app_ctx = RB_tree_new(idi_cmp_app_ctx, free_payload);
	lwres_register(idc);
    } else {
	free(idc);
	idc = NULL;
    }
#endif
    return idc;
}

void io_dns_cancel(struct io_dns_ctx *idc, void *app_ctx)
{
    struct io_dns_item i;
    rb_node_t *r;
    i.app_ctx = app_ctx;
    if ((r = RB_search(idc->by_app_ctx, &i))) {
#ifdef WITH_LWRES
	RB_search_and_delete(idc->by_serial, RB_payload(r, void *));
#endif
#ifdef WITH_ARES
	RB_search_and_delete(idc->by_addr, RB_payload(r, void *));
#endif
	RB_delete(idc->by_app_ctx, r);
    }
}

void io_dns_destroy(struct io_dns_ctx *idc)
{
#ifdef WITH_ARES
    RB_tree_delete(idc->by_addr);
#endif
#ifdef WITH_LWRES
    int sock = lwres_context_getsocket(idc->ctx);
    if (idc->registered && sock > -1)
	io_unregister(idc->io, sock);
    RB_tree_delete(idc->by_serial);
#endif
    RB_tree_delete(idc->by_app_ctx);
#ifdef WITH_ARES
    ares_destroy(idc->channel);
    idc->channel = NULL;
#endif
#ifdef WITH_LWRES
    lwres_context_destroy(&idc->ctx);
#endif
    free(idc);
}

void io_dns_add_addr(struct io_dns_ctx *idc, struct in6_addr *a, void *app_cb, void *app_ctx)
{
    if (idc) {
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
}

#ifdef WITH_ARES
static void a_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen);

void io_dns_add(struct io_dns_ctx *idc, sockaddr_union * su, void *app_cb, void *app_ctx)
{
    char hex[] = "0123456789abcdef";
    char query[100];
    char *t = query;
    int i;
    struct io_dns_item *idi = Xcalloc(1, sizeof(struct io_dns_item));

    switch (su->sa.sa_family) {
#ifdef AF_INET
    case AF_INET:
	snprintf(query, sizeof(query), "%u.%u.%u.%u.in-addr.arpa",
		 (su->sin.sin_addr.s_addr >> 24) & 0xff,
		 (su->sin.sin_addr.s_addr >> 16) & 0xff, (su->sin.sin_addr.s_addr >> 8) & 0xff, su->sin.sin_addr.s_addr & 0xff);
	break;
#endif				/* AF_INET */
#ifdef AF_INET6
    case AF_INET6:
	for (i = 15; i > -1; i--) {
	    *t++ = hex[((char *) su->sin6.sin6_addr.s6_addr32)[i >> 2] & 0xf];
	    *t++ = '.';
	    *t++ = hex[((char *) su->sin6.sin6_addr.s6_addr32)[i >> 2] >> 4];
	    *t++ = '.';
	}
	strcpy(t, "IP6.ARPA");
#endif				/* AF_INET6 */
    }

    idi->idc = idc;
    idi->app_cb = app_cb;
    idi->app_ctx = app_ctx;
    RB_insert(idc->by_addr, idi);
    RB_insert(idc->by_app_ctx, idi);
    ares_query(idc->channel, query, C_IN, T_PTR, a_callback, idi);
    io_ares_set(idc);
}
#endif
#ifdef WITH_LWRES
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
	    struct io_dns_item *idi = Xcalloc(1, sizeof(struct io_dns_item));
	    idi->serial = serial;
	    idi->app_cb = app_cb;
	    idi->app_ctx = app_ctx;
	    RB_insert(idc->by_serial, idi);
	    RB_insert(idc->by_app_ctx, idi);

	    if (!idc->registered)
		lwres_register(idc);

	}
	free(b.base);
    }
}
#endif

#ifdef WITH_ARES
static void a_callback(void *arg, int status, int timeouts __attribute__((unused)), unsigned char *abuf, int alen)
{
    struct io_dns_item *idi = (struct io_dns_item *) arg;
    rb_node_t *r = RB_search(idi->idc->by_addr, arg);
    struct io_dns_item *p = r ? RB_payload(r, struct io_dns_item *) : NULL;
    char *res = NULL;
    struct hostent *host = NULL;

    if (status == ARES_SUCCESS) {
	status = ares_parse_ptr_reply(abuf, alen, NULL, 0, AF_INET, &host);
	if (status == ARES_SUCCESS && p && host)
	    res = host->h_name;
    }
    if (p)
	((void (*)(void *, char *)) p->app_cb) (p->app_ctx, res);
    if (host)
	ares_free_hostent(host);
    if (p)
	RB_search_and_delete(idi->idc->by_app_ctx, p);
    if (r)
	RB_delete(idi->idc->by_addr, r);
}
#endif
#ifdef WITH_LWRES
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
#endif

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
