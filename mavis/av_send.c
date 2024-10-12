/*
 * av_send.c
 *
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "misc/sysconf.h"
#include "av_send.h"
#include "mavis.h"
#include "debug.h"
#include "blowfish.h"
#include "misc/io.h"
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

static const char rcsid[] __attribute__((used)) = "$Id$";

int av_send(av_ctx * ac, int sock, sockaddr_union * sa, struct blowfish_ctx *blowfish)
{
    DebugIn(DEBUG_MAVIS);

    a_char av_buffer[BUFSIZE_MAVIS / sizeof(u_long)];

    ssize_t buflen = av_array_to_char(ac, av_buffer->s, BUFSIZE_MAVIS - 1, NULL);
    if (buflen < 0)
	return MAVIS_IGNORE;
    av_buffer->s[buflen] = 0;

    if (blowfish)
	buflen = blowfish_enc(blowfish, av_buffer, buflen + 1);

    ssize_t result = Sendto(sock, av_buffer->s, buflen, 0, &sa->sa, su_len(sa));

    Debug((DEBUG_MAVIS, "- %s = %ld\n", __func__, (long) result));
    return (result == buflen) ? MAVIS_DEFERRED : MAVIS_IGNORE;
}
