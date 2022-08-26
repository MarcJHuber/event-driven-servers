/*
 * conversions.c
 *
 * (C)2000-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

struct conv_table {
    char conv;
    char *ext;
    int len;
};

static struct conv_table conv_table[] = {
    { CONV_MD5, ".md5", 4 },
    { CONV_MD5, ".MD5", 4 },
    { CONV_CRC, ".crc", 4 },
    { CONV_CRC, ".CRC", 4 },
#ifdef WITH_ZLIB
    { CONV_GZ, ".gz", 3 },
    { CONV_GZ, ".GZ", 3 },
#endif
    { CONV_NONE, NULL, 0 }
};

int convstat(struct context *ctx, struct stat *st, char *path)
{
    struct conv_table *ct = conv_table;
    char conv = CONV_NONE;
    ssize_t len;

    DebugIn(DEBUG_PROC);

    len = strlen(path);
    for (ct = conv_table; ct->ext && conv == CONV_NONE; ct++)
	if (ct->len < len && !strcmp(path + len - ct->len, ct->ext))
	    conv = ct->conv;

    ctx->conversion = CONV_NONE;

    switch (conv) {
    case CONV_MD5:
	path[len - ct->len] = 0;
	if (pickystat(ctx, st, path))
	    path[len - ct->len] = ct->ext[0];
	else {
	    myMD5Init(&ctx->checksum.md5context);
	    ctx->conversion = conv;
	}
	break;
    case CONV_CRC:
	path[len - ct->len] = 0;
	if (pickystat(ctx, st, path))
	    path[len - ct->len] = ct->ext[0];
	else {
	    ctx->conversion = conv;
	    ctx->bytecount = 0;
	    ctx->checksum.crc32 = INITCRC32;
	}
	break;
    case CONV_GZ:
	path[len - ct->len] = 0;
	if (ctx->mode == 'z' || pickystat(ctx, st, path))
	    path[len - ct->len] = ct->ext[0];
	else
	    ctx->conversion = conv;
	break;
    default:
	;
    }
    DebugOut(DEBUG_PROC);
    return (ctx->conversion == CONV_NONE);
}
