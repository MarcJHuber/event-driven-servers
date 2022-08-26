/*
 * structs.c
 * (C)1999-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"
#include <arpa/telnet.h>

static const char rcsid[] __attribute__((used)) = "$Id$";

struct context *new_context(struct io_context *io)
{
    struct context *c = Xcalloc(1, sizeof(struct context));

    c->io = io;
    c->cfn = c->dfn = c->ffn = c->dirfn = c->ifn = c->sctp_fn = -1;
    c->outgoing_data = c->use_ascii = 1;
    c->state = ST_conn;
    c->uid = -1;
    c->gid = -1;
    c->umask = 022;
    c->mlst_facts = MLST_fact_size | MLST_fact_modify | MLST_fact_type | MLST_fact_unique | MLST_fact_perm;
    c->protected_buffer_size = -1;
    c->io_offset_end = -1;
    c->multiline_banners = 1;
    c->iac[0] = IAC;
    c->mode = 's';
    c->md_method_hash = c->md_method_checksum = md_method_find(md_methods, "SHA-1");
    if (!c->md_method_hash)
	c->md_method_hash = c->md_method_checksum = md_method_find(md_methods, "MD5");

    return c;
}
