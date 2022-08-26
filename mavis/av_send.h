/*
 * av_send.h
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 *
 * $Id: av_send.h,v 1.7 2011/07/17 19:12:19 marc Exp $
 *
 */

#ifndef __AV_SEND_H__
#define __AV_SEND_H__

#include <sys/types.h>
#include "mavis/mavis.h"
#include "mavis/blowfish.h"
#include "misc/net.h"

int av_send(av_ctx *, int, sockaddr_union *, struct blowfish_ctx *);

#endif				/* __AV_SEND_H__ */
