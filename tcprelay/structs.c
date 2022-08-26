/*
 * structs.c
 * (C)1999-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

struct context *new_context(struct io_context *io)
{
    struct context *c = Xcalloc(1, sizeof(struct context));
    c->io = io;
    c->ifn = c->ofn = -1;
    c->con_arr_idx = -1;

    return c;
}
