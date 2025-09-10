/*
   Copyright (C) 1999-2023 Marc Huber (Marc.Huber@web.de)
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

#include <stdio.h>
#include "config_radius.h"
#include "misc/version.h"
#include "misc/strops.h"
#include "misc/net.h"
#include "misc/mymd5.h"
#include <setjmp.h>

#ifdef WITH_PCRE2
#include <pcre2.h>
#endif

#include <regex.h>

#ifdef WITH_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#endif

static const char rcsid[] __attribute__((used)) = "$Id$";

struct rad_dict *global_rad_dict = NULL;

int rad_dict_initialized(void)
{
    return global_rad_dict != NULL;
}

static struct rad_dict *rad_dict_new(struct sym *sym, char *name, int id)
{
    struct rad_dict **dict = &global_rad_dict;
    while (*dict)
	dict = &(*dict)->next;
    *dict = calloc(1, sizeof(struct rad_dict));
    str_set(&(*dict)->name, strdup(name), 0);
    (*dict)->line = sym->line;
    (*dict)->id = id;
    return *dict;
}

struct rad_dict *rad_dict_lookup_by_id(int vendorid)
{
    for (struct rad_dict * dict = global_rad_dict; dict; dict = dict->next)
	if (dict->id == vendorid)
	    return dict;
    return NULL;
}

struct rad_dict *rad_dict_lookup_by_name(char *vendorname)
{
    size_t vendorname_len = strlen(vendorname);
    for (struct rad_dict * dict = global_rad_dict; dict; dict = dict->next)
	if (dict->name.len == vendorname_len && !strcmp(dict->name.txt, vendorname))
	    return dict;
    return NULL;
}

struct rad_dict_attr *rad_dict_attr_lookup_by_id(struct rad_dict *dict, int id)
{
    for (struct rad_dict_attr * attr = dict->attr; attr; attr = attr->next)
	if (attr->id == id)
	    return attr;
    return NULL;
}

struct rad_dict_attr *rad_dict_attr_lookup_by_name(struct rad_dict *dict, char *name)
{
    size_t name_len = strlen(name);
    for (struct rad_dict_attr * attr = dict->attr; attr; attr = attr->next)
	if (attr->name.len == name_len && !strcmp(attr->name.txt, name))
	    return attr;
    return NULL;
}

struct rad_dict_val *rad_dict_val_lookup_by_id(struct rad_dict_attr *attr, int id)
{
    for (struct rad_dict_val * val = attr->val; val; val = val->next)
	if (val->id == id)
	    return val;
    return NULL;
}

struct rad_dict_val *rad_dict_val_lookup_by_name(struct rad_dict_attr *attr, char *name)
{
    size_t name_len = strlen(name);
    for (struct rad_dict_val * val = attr->val; val; val = val->next)
	if (val->name.len == name_len && !strcmp(val->name.txt, name))
	    return val;
    return NULL;
}

static struct rad_dict_attr *rad_dict_attr_add(struct sym *sym, struct rad_dict *dict, char *name, int id, enum token type)
{
    struct rad_dict_attr **attr = &(dict->attr);
    while (*attr)
	attr = &(*attr)->next;
    *attr = calloc(1, sizeof(struct rad_dict_attr));
    str_set(&(*attr)->name, strdup(name), 0);
    (*attr)->line = sym->line;
    (*attr)->id = id;
    (*attr)->dict = dict;
    (*attr)->type = type;
    return *attr;
}

static void rad_dict_attr_add_val(struct sym *sym, struct rad_dict_attr *attr, char *name, int id)
{
    struct rad_dict_val **val = &(attr->val);
    while (*val)
	val = &(*val)->next;
    *val = calloc(1, sizeof(struct rad_dict_val));
    str_set(&(*val)->name, strdup(name), 0);
    (*val)->line = sym->line;
    (*val)->id = id;
}

struct rad_dict_attr *rad_dict_attr_lookup(struct sym *sym)
{
    size_t buf_len = strlen(sym->buf);
    char *vid_str = alloca(buf_len + 1);
    memcpy(vid_str, sym->buf, buf_len + 1);
    char *id_str = strchr(vid_str, ':');

    if (id_str) {
	*id_str = 0;
	id_str++;
    } else {
	id_str = sym->buf;
	vid_str = "";
    }

    struct rad_dict *dict = rad_dict_lookup_by_name(vid_str);
    if (!dict)
	parse_error(sym, "RADIUS dictionary '%s' unknown", vid_str);

    struct rad_dict_attr *attr = rad_dict_attr_lookup_by_name(dict, id_str);
    if (!attr)
	parse_error(sym, "RADIUS attribute '%s' unknown", sym->buf);

    return attr;
}

static void rad_attr_val_dump_hex(u_char *data, size_t data_len, char **buf, size_t *buf_len)
{
    char hex[16] = "0123456789abcdef";
    for (size_t i = 0; i < data_len && *buf_len > 10; i++) {
	if (i) {
	    *(*buf)++ = ' ';
	    (*buf_len)--;
	}

	*(*buf)++ = hex[data[i] >> 4];
	*(*buf)++ = hex[data[i] & 15];
	*buf_len -= 2;
    }
}

static void rad_attr_val_dump_helper(u_char *data, size_t data_len, char **buf, size_t *buf_len, struct rad_dict *dict)
{
    // dump exactly one av pair, type is attr->type, prefixed with attr->dict->name (vendor name)

    if (dict->id > -1 && *buf_len > dict->name.len + 2) {
	memcpy(*buf, dict->name.txt, dict->name.len);
	*buf += dict->name.len;
	*buf_len -= dict->name.len;
	*(*buf)++ = ':';
	*buf_len -= 1;
    }
    struct rad_dict_attr *attr = rad_dict_attr_lookup_by_id(dict, *data);

    if (attr) {
	if (*buf_len > attr->name.len + 2) {
	    memcpy(*buf, attr->name.txt, attr->name.len);
	    *buf += attr->name.len;
	    *buf_len -= attr->name.len;
	    *(*buf)++ = '=';
	    *buf_len -= 1;
	}
	switch (attr->type) {
	case S_string_keyword:
	    if (*buf_len > (size_t) (data[1] - 1)) {
		if (attr->dict->id == -1 && attr->id == RADIUS_A_USER_PASSWORD) {
		    *(*buf)++ = '*';
		    *(*buf)++ = '*';
		    *(*buf)++ = '*';
		    *buf_len -= 3;
		} else {
		    memcpy(*buf, data + 2, data[1] - 2);
		    *buf += data[1] - 2;
		    *buf_len -= data[1] - 2;
		}
	    }
	    break;
	case S_enum:
	case S_time:
	case S_integer:
	    if (data[1] == 6) {
		u_int i = (data[2] << 24) | (data[3] << 16) | (data[4] << 8) | data[5];
		struct rad_dict_val *val = rad_dict_val_lookup_by_id(attr, i);
		if (val && (*buf_len > val->name.len)) {
		    memcpy(*buf, val->name.txt, val->name.len);
		    *buf += val->name.len;
		    *buf_len -= val->name.len;
		} else {
		    int len = snprintf(*buf, *buf_len, "%u", i);
		    if (len > 0) {
			*buf += len;
			*buf_len -= len;
		    }
		}
	    }
	    break;
	case S_octets:
	    rad_attr_val_dump_hex(data + 2, data_len - 2, buf, buf_len);
	    return;
	case S_address:
	case S_ipaddr:
	case S_ipv4addr:
	    if (data[1] == 6) {
		sockaddr_union from = { 0 };
		from.sin.sin_family = AF_INET;
		memcpy(&from.sin.sin_addr, data + 2, 4);
		if (su_ntoa(&from, *buf, *buf_len)) {
		    int len = strlen(*buf);
		    *buf += len;
		    *buf_len -= len;
		}
	    }
	    break;
	case S_ipv6addr:
	    if (data[1] == 18) {
		sockaddr_union from = { 0 };
		from.sin.sin_family = AF_INET6;
		memcpy(&from.sin6.sin6_addr, data + 2, 16);
		if (su_ntoa(&from, *buf, *buf_len)) {
		    int len = strlen(*buf);
		    *buf += len;
		    *buf_len -= len;
		}
	    }
	    break;
	default:
	    ;
	}
    } else {
	rad_attr_val_dump_hex(data, data[1], buf, buf_len);
    }
}

void rad_attr_val_dump(mem_t *mem, u_char *data, size_t data_len, char **buf, size_t *buf_len, struct rad_dict *dict, char *separator, size_t separator_len)
{
    char *buf_start = NULL;
    if (!dict)
	dict = rad_dict_lookup_by_id(-1);
    if (!*buf) {
	*buf_len = 4096;
	*buf = mem_alloc(mem, *buf_len);
	buf_start = *buf;
    }

    u_char *data_end = data + data_len;

    int add_separator = 0;
    while (data < data_end) {
	u_char *d_start = data;
	size_t d_len = data[1];
	struct rad_dict *cur_dict = dict;
	if (dict->id == -1 && data[0] == RADIUS_A_VENDOR_SPECIFIC && data[1] > 6) {
	    int vendorid = (data[2] << 24) | (data[3] << 16) | (data[4] << 8) | (data[5] << 0);
	    cur_dict = rad_dict_lookup_by_id(vendorid);
	    if (cur_dict) {
		d_start = data + 6;
		d_len = data[1] - 6;
	    }
	}

	if (dict->id != -1 || ( /* *d_start != RADIUS_A_MESSAGE_AUTHENTICATOR && */ *d_start != RADIUS_A_USER_PASSWORD)) {
	    if (cur_dict) {
		while (d_len > 0) {
		    if (add_separator) {
			if (*buf_len > separator_len) {
			    memcpy(*buf, separator, separator_len);
			    *buf += separator_len;
			    *buf_len -= separator_len;
			}
		    }
		    rad_attr_val_dump_helper(d_start, d_len, buf, buf_len, cur_dict);
		    if (!d_start[1])
			return;
		    d_len -= d_start[1];
		    d_start += d_start[1];
		    add_separator = 1;
		}
	    } else {
		if (add_separator) {
		    if (*buf_len > separator_len) {
			memcpy(*buf, separator, separator_len);
			*buf += separator_len;
			*buf_len -= separator_len;
		    }
		}
		rad_attr_val_dump_hex(d_start, d_len, buf, buf_len);
		add_separator = 1;
	    }
	}
	if (data < data_end || !data[1])
	    return;
	*data += data[1];

    }
    *(*buf) = 0;
    if (buf_start) {
	*buf_len = (*buf - buf_start);
	*buf = buf_start;
	// assert (*buf_len == strlen(buf_start));
    }
}

char *rad_attr_val_dump1(mem_t *mem, u_char **data, size_t *data_len)
{
    if (*data_len < 3 || !(*data)[1])
	return NULL;

    struct rad_dict *dict = rad_dict_lookup_by_id(-1);
    size_t buf_len = 4096;
    char *buf_start = mem_alloc(mem, buf_len);
    char *buf = buf_start;

    u_char *d_start = *data;
    size_t d_len = (*data)[1];
    if (!d_len)
	return NULL;
    struct rad_dict *cur_dict = dict;
    if (dict->id == -1 && (*data)[0] == RADIUS_A_VENDOR_SPECIFIC && (*data)[1] > 6) {
	int vendorid = ((*data)[2] << 24) | ((*data)[3] << 16) | ((*data)[4] << 8) | ((*data)[5] << 0);
	cur_dict = rad_dict_lookup_by_id(vendorid);
	if (cur_dict) {
	    d_start = (*data) + 6;
	    d_len = (*data)[1] - 6;
	    if (!d_len)
		return NULL;
	}
    }

    if (dict->id != -1 || (*d_start != RADIUS_A_USER_PASSWORD)) {
	if (cur_dict) {
	    while (d_len > 0) {
		rad_attr_val_dump_helper(d_start, d_len, &buf, &buf_len, cur_dict);
		d_len -= d_start[1];
		d_start += d_start[1];
		if (!d_start[1])
		    return NULL;
	    }
	} else {
	    rad_attr_val_dump_hex(d_start, d_len, &buf, &buf_len);
	}
    }
    *data = d_start;
    *data_len = d_len;

    return buf_start;
}

void rad_dict_get_val(int dict_id, int attr_id, int val_id, char **s, size_t *s_len)
{
    struct rad_dict *dict = rad_dict_lookup_by_id(dict_id);
    if (dict) {
	struct rad_dict_attr *attr = rad_dict_attr_lookup_by_id(dict, attr_id);
	if (attr) {
	    for (struct rad_dict_val * val = rad_dict_val_lookup_by_id(attr, attr_id); val; val = val->next)
		if (val->id == val_id) {
		    *s = val->name.txt;
		    *s_len = val->name.len;
		    return;
		}
	}
    }
}

void parse_radius_dictionary(struct sym *sym)
{
    struct rad_dict *dict = NULL;
    sym_get(sym);
    if (sym->code == S_openbra) {
	dict = rad_dict_lookup_by_id(-1);
	if (!dict)
	    dict = rad_dict_new(sym, "", -1);
    } else {
	char *vendor = NULL;
	int vendorid = -1;
	dict = rad_dict_lookup_by_name(sym->buf);
	if (!dict)
	    vendor = strdup(sym->buf);
	sym_get(sym);
	vendorid = parse_int(sym);
	if (dict && dict->id != vendorid)
	    parse_error(sym, "RADIUS dictionary '%s', already defined at line %d, with vendor id %d", sym->buf, dict->line, dict->id);
	if (vendorid < 1)
	    parse_error(sym, "Expected a valid vendor number but got '%s'", sym->buf);
	struct rad_dict *dict_by_id = rad_dict_lookup_by_id(vendorid);
	if (dict && dict != dict_by_id)
	    parse_error(sym, "RADIUS dictionary id %d is already defined at line %d, with vendor name %s", sym->buf, dict->id, dict->line, dict->name);
	if (!dict)
	    dict = rad_dict_new(sym, vendor, vendorid);
	free(vendor);
    }
    parse(sym, S_openbra);
    while (sym->code == S_attr) {
	sym_get(sym);
	char *name = strdup(sym->buf);
	sym_get(sym);
	int id = parse_int(sym);
	if (!id || (id & ~0xff))
	    parse_error(sym, "Expected a number from 1 to 255 but got '%s'", sym->buf);
	enum token type = sym->code;
	switch (type) {
	case S_string_keyword:
	case S_octets:
	case S_address:
	case S_ipaddr:
	case S_ipv4addr:
	case S_ipv6addr:
	case S_enum:
	case S_integer:
	case S_time:
	case S_vsa:
	    break;
	default:
	    parse_error_expect(sym, S_string_keyword, S_octets, S_address, S_ipaddr, S_ipv4addr, S_ipv6addr, S_enum, S_integer, S_time, S_vsa, S_unknown);
	}
	sym_get(sym);
	struct rad_dict_attr *attr = rad_dict_attr_add(sym, dict, name, id, type);
	free(name);
	if ((type == S_integer || type == S_time || type == S_enum) && sym->code == S_openbra) {
	    sym_get(sym);
	    while (sym->code != S_closebra && sym->code != S_eof) {
		name = strdup(sym->buf);
		sym_get(sym);
		id = parse_int(sym);
		rad_dict_attr_add_val(sym, attr, name, id);
		free(name);
	    }
	    parse(sym, S_closebra);
	}
    }
    parse(sym, S_closebra);
}

static int rad_get_helper(mem_t *mem, enum token type, void *val, size_t *val_len, u_char *data, size_t data_len)
{
    if (val)
	switch (type) {
	case S_string_keyword:{
		char **s = (char **) val;
		*s = mem_strndup(mem, data, data_len);
		if (val_len)
		    *val_len = data_len;
		return 0;
	    }
	case S_address:
	case S_ipaddr:
	case S_ipv4addr:
	    if (data_len != 4)
		return -1;
	    memcpy(val, data, 4);
	    if (val_len)
		*val_len = data_len;
	    return 0;
	case S_ipv6addr:
	    if (data_len != 16)
		return -1;
	    memcpy(val, data, 16);
	    if (val_len)
		*val_len = data_len;
	    return 0;
	case S_time:
	case S_enum:
	case S_integer:{
		if (data_len != 4)
		    return -1;
		int32_t i, *p = (int32_t *) val;
		memcpy(&i, data, 4);
		*p = ntohl(i);
		if (val_len)
		    *val_len = data_len;
		return 0;
	    }
	case S_octets:{
		u_char **s = (u_char **) val;
		*s = mem_copy(mem, data, data_len);
		if (val_len)
		    *val_len = data_len;
		return 0;
	    }
	default:
	    ;
	}
    return -1;
}

int rad_get(rad_pak_hdr *pak_in, mem_t *mem, int vendorid, int id, enum token type, void *val, size_t *val_len)
{
    struct rad_dict *dict = rad_dict_lookup_by_id(vendorid);
    if (dict) {
	u_char *p = RADIUS_DATA(pak_in);
	size_t len = RADIUS_DATA_LEN(pak_in);
	u_char *e = p + len;
	while (p < e) {
	    if (vendorid == -1 && p[0] == id)
		return rad_get_helper(mem, type, val, val_len, p + 2, p[1] - 2);
	    if (vendorid > -1 && p[0] == RADIUS_A_VENDOR_SPECIFIC && p[2] == ((vendorid >> 24) & 0xff)
		&& p[3] == ((vendorid >> 16) & 0xff)
		&& p[4] == ((vendorid >> 8) & 0xff)
		&& p[5] == ((vendorid >> 0) & 0xff)) {
		u_char *ve = p + p[1];
		u_char *vp = p + 6;
		while (vp < ve && vp[1] > 1) {
		    if (vp[0] == id)
			return rad_get_helper(mem, type, val, val_len, vp + 2, vp[1] - 2);
		    vp += vp[1];
		}
	    }
	    if (!p[1])		// packet malformed, attribut length zero
		return -1;
	    p += p[1];
	}
    }
    return -1;
}
