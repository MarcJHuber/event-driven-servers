/*
 * buffer.h
 * (C)1997-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id: buffer.h,v 1.7 2011/02/27 12:22:16 marc Exp $
 *
 */

#ifndef __BUFFER_H__
#define __BUFFER_H__

#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/uio.h>

struct buffer {
    size_t length;
    size_t offset;
    size_t size;
    char *buf;
    struct buffer *next;
    int mmapped;
};

struct buffer *buffer_get(void);
struct buffer *buffer_free(struct buffer *);
struct buffer *buffer_free_all(struct buffer *);
void buffer_setsize(size_t, int);
size_t buffer_getsize(size_t *, size_t *);
size_t buffer_setv(struct buffer *, struct iovec *, int *, size_t);
struct buffer *buffer_release(struct buffer *, off_t *);
#ifdef WITH_MMAP
void buffer_sequential(struct buffer *, size_t);
void buffer_sequential_all(struct buffer *);
#else
#define buffer_sequential(dummy)
#define buffer_sequential_all(dummy)
#endif
struct buffer *buffer_append(struct buffer *, struct buffer *);
size_t buffer_getlen(struct buffer *);
int buffer_strncmp(struct buffer *, char *, size_t, size_t);
int buffer_chrcmp(struct buffer *, char, size_t);
void buffer_strncpy(struct buffer *, char *, size_t, size_t);
int buffer_chr(struct buffer *, int, size_t, size_t);
struct buffer *buffer_write(struct buffer *, char *, size_t);
#define buffer_print(A,B) buffer_write(A,B,strlen(B))
struct buffer *buffer_printf(struct buffer *, char *, ...);
struct buffer *buffer_truncate(struct buffer *, size_t);
void buffer_destroy(void);
#ifdef WITH_MMAP
struct buffer *buffer_get_mmap(void);
#endif				/* WITH_MMAP */

#endif				/* __BUFFER_H__ */
