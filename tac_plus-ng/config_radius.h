/*
   Copyright (C) 1999-2022 Marc Huber (Marc.Huber@web.de)

   All rights reserved.

   Redistribution and use in source and binary  forms,  with or without
   modification, are permitted provided  that  the following conditions
   are met:

   1. Redistributions of source code  must  retain  the above copyright
      notice, this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions  and  the following disclaimer in
      the  documentation  and/or  other  materials  provided  with  the
      distribution.

   3. The end-user documentation  included with the redistribution,  if
      any, must include the following acknowledgment:

          This product includes software developed by Marc Huber
	  (Marc.Huber@web.de).

      Alternately,  this  acknowledgment  may  appear  in  the software
      itself, if and wherever such third-party acknowledgments normally
      appear.

   THIS SOFTWARE IS  PROVIDED  ``AS IS''  AND  ANY EXPRESSED OR IMPLIED
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
   IN NO EVENT SHALL  ITS  AUTHOR  BE  LIABLE FOR ANY DIRECT, INDIRECT,
   INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
   BUT NOT LIMITED  TO,  PROCUREMENT OF  SUBSTITUTE  GOODS OR SERVICES;
   LOSS OF USE,  DATA,  OR PROFITS;  OR  BUSINESS INTERRUPTION) HOWEVER
   CAUSED AND ON ANY THEORY OF LIABILITY,  WHETHER IN CONTRACT,  STRICT
   LIABILITY,  OR TORT  (INCLUDING NEGLIGENCE OR OTHERWISE)  ARISING IN
   ANY WAY OUT OF THE  USE  OF  THIS  SOFTWARE,  EVEN IF ADVISED OF THE
   POSSIBILITY OF SUCH DAMAGE.
 */

/* $Id$ */

#ifndef __CONFIG_RADIUS_H_
#define __CONFIG_RADIUS_H_

#ifndef RAD_NAME_ATTRIBUTES
#define RAD_NAME_ATTRIBUTES str_t name
#endif
#include "misc/str.h"
#include "mavis/mavis.h"
#include "mavis/token.h"
#include "protocol_radius.h"

struct rad_dict_val {
    RAD_NAME_ATTRIBUTES;
    struct rad_dict_val *next;
    int line;
    int id;
};

struct rad_dict_attr {
    RAD_NAME_ATTRIBUTES;
    struct rad_dict_attr *next;
    int line;
    int id;
    enum token type;
    struct rad_dict *dict;	// back-reference to vendor
    struct rad_dict_val *val;
};

struct rad_dict {
    RAD_NAME_ATTRIBUTES;
    struct rad_dict *next;
    int line;
    int id;
    struct rad_dict_attr *attr;
};

void parse_radius_dictionary(struct sym *sym);
int rad_get(rad_pak_hdr * pak_in, mem_t * mem, int vendorid, int id, enum token, void *, size_t *);
void rad_attr_val_dump(mem_t * mem, u_char * data, size_t data_len, char **buf, size_t *buf_len, struct rad_dict *dict, char *separator,
		       size_t separator_len);

int rad_dict_initialized(void);

void rad_dict_get_val(int dict_id, int attr_id, int val_id, char **s, size_t *s_len);

struct rad_dict *rad_dict_lookup_by_id(int vendorid);
struct rad_dict_attr *rad_dict_attr_lookup_by_id(struct rad_dict *dict, int id);
struct rad_dict_val *rad_dict_val_lookup_by_id(struct rad_dict_attr *attr, int id);
struct rad_dict_attr *rad_dict_attr_lookup_by_id(struct rad_dict *dict, int id);
struct rad_dict_attr *rad_dict_attr_lookup(struct sym *sym);
struct rad_dict_val *rad_dict_val_lookup_by_name(struct rad_dict_attr *attr, char *name);
struct rad_dict *rad_dict_lookup_by_name(char *vendorname);
struct rad_dict_attr *rad_dict_attr_lookup_by_name(struct rad_dict *dict, char *name);

#endif				/* __CONFIG_RADIUS_H_ */
/*
 * vim:ts=4
 */
