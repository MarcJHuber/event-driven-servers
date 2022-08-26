/*
 * buffer.c
 * (C)1997-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include <stdlib.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <limits.h>
#include <string.h>

#include "misc/sysconf.h"
#include "misc/buffer.h"
#include "misc/memops.h"
#include "mavis/debug.h"
#include "mavis/log.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

#ifndef BUFSIZE
#define BUFSIZE 32768
#endif

#define MIN(A,B) (A < B ? A : B)

static struct buffer *freelist = NULL;

#ifdef WITH_MMAP
static struct buffer *mmap_freelist = NULL;
#endif				/* WITH_MMAP */

static size_t bufsize = BUFSIZE;
static int buffercount = 0;
static int maxpoolsize = 0;

struct buffer *buffer_free(struct buffer *b)
{
    struct buffer *next = NULL;
    Debug((DEBUG_BUFFER, "buffer_free (%p)\n", b));

    if (b) {
	next = b->next;
#ifdef WITH_MMAP
	if (b->mmapped) {
	    if (b->buf != MAP_FAILED) {
		munmap(b->buf, b->size);
		b->buf = MAP_FAILED;
	    }

	    b->next = mmap_freelist;
	    mmap_freelist = b;
	} else
#endif				/* WITH_MMAP */
	{
	    if (maxpoolsize && buffercount > maxpoolsize) {
		free(b);
		buffercount--;
	    } else {
		b->next = freelist;
		freelist = b;
	    }
	}
    }
    return next;
}

struct buffer *buffer_get()
{
    struct buffer *b;

    if (freelist) {
	b = freelist;
	freelist = freelist->next;
	b->length = b->offset = 0, b->next = NULL;
    } else {
	b = (struct buffer *) Xcalloc(1, sizeof(struct buffer) + bufsize);
	b->buf = (char *) (b + 1);
	b->size = bufsize;
	buffercount++;
    }
    Debug((DEBUG_BUFFER, "buffer_get = %p\n", b));
    return b;
}

struct buffer *buffer_free_all(struct buffer *b)
{
    for (; b; b = buffer_free(b));
    return NULL;
}

void buffer_setsize(size_t b, int m)
{
    bufsize = b;
    maxpoolsize = m;
}

size_t buffer_getsize(size_t *b, size_t *m)
{
    if (b)
	*b = bufsize;
    if (m)
	*m = maxpoolsize;
    return bufsize;
}

size_t buffer_getlen(struct buffer *b)
{
    size_t len = 0;

    for (; b; b = b->next)
	len += b->length - b->offset;
    return len;
}

size_t buffer_setv(struct buffer *b, struct iovec *vector, int *count, size_t n)
{
    size_t len = 0;
    int i;
    if (n) {
	for (i = 0; i < *count && b && n; i++, b = b->next) {
	    size_t min = MIN(n, b->length - b->offset);
	    vector[i].iov_base = b->buf + b->offset;
	    vector[i].iov_len = min;
	    n -= min, len += min;
	}
    } else {
	for (i = 0; i < *count && b; i++, b = b->next) {
	    size_t min = b->length - b->offset;
	    vector[i].iov_base = b->buf + b->offset;
	    vector[i].iov_len = min;
	    len += min;
	}
    }
    *count = i;
    return len;
}

#ifdef WITH_MMAP
void buffer_sequential(struct buffer *b, size_t len)
{
    Debug((DEBUG_BUFFER, "sequential %d\n", (int) len));
    while (len && b) {
	Debug((DEBUG_BUFFER, "  sequential %d\n", (int) len));
	if (len >= b->length - b->offset) {
	    len -= b->length - b->offset;
	    if (b->mmapped)
		madvise(b->buf, b->length, MADV_SEQUENTIAL);
	    b = b->next;
	} else {
	    if (b->mmapped)
		madvise(b->buf, len, MADV_SEQUENTIAL);
	    len = 0;
	}
    }
}

void buffer_sequential_all(struct buffer *b)
{
    Debug((DEBUG_BUFFER, "sequential_all\n"));
    for (; b; b = b->next) {
	Debug((DEBUG_BUFFER, "b=%p next=%p\n", b, b->next));
	if (b->mmapped)
	    madvise(b->buf, b->size, MADV_SEQUENTIAL);
    }
}
#endif				/* WITH_MMAP */

struct buffer *buffer_release(struct buffer *b, off_t * len)
{
    Debug((DEBUG_BUFFER, "buffer_release (%p, %ld)\n", b, (long) *len));
    while (*len && b) {
	if (*len >= (off_t) (b->length - b->offset)) {
	    *len -= b->length - b->offset;
	    b = buffer_free(b);
	} else {
	    b->offset += (size_t) (*len);
#ifdef WITH_MMAP
	    if (b->mmapped)
		madvise(b->buf, b->offset, MADV_DONTNEED);
#endif				/* WITH_MMAP */
	    *len = 0;
	}
    }
    while (b && (b->length == b->offset))
	b = buffer_free(b);
    Debug((DEBUG_BUFFER, "buffer_release = %p\n", b));
    return b;
}

struct buffer *buffer_append(struct buffer *a, struct buffer *b)
{
    Debug((DEBUG_BUFFER, "buffer_append(%p, %p)\n", a, b));
    if (a) {
	struct buffer *c = a;
	while (c->next)
	    c = c->next;
	c->next = b;
    } else
	a = b;
    Debug((DEBUG_BUFFER, "buffer_append = %p\n", a));
    return a;
}

int buffer_strncmp(struct buffer *b, char *s, size_t n, size_t o)
{
    Debug((DEBUG_BUFFER, "buffer_strncmp (\"%.*s\") offset %d\n", (int) n, s, (int) o));
    while (b && (size_t) (b->length - b->offset) <= o) {
	o -= b->length - b->offset;
	b = b->next;
    }

    while (b && n) {
	size_t min = MIN(n, b->length - b->offset - o);
	int r = strncmp(s, b->buf + b->offset + o, min);
	Debug((DEBUG_BUFFER, " \"%.*s\"  <-> \"%.*s\"\n", (int) min, s, (int) min, b->buf + b->offset + o));
	if (!r)
	    return 0;
	o = 0, s += min, n -= min, b = b->next;
    }
    return -1;
}

int buffer_chrcmp(struct buffer *b, char c, size_t o)
{
    while (b && (size_t) (b->length - b->offset) <= o) {
	o -= b->length - b->offset;
	b = b->next;
    }

    if (b)
	return c - *(b->buf + b->offset + o);
    return -1;
}

void buffer_strncpy(struct buffer *b, char *s, size_t n, size_t o)
{
    while (b && (size_t) (b->length - b->offset) <= o) {
	o -= b->length - b->offset;
	b = b->next;
    }

    while (b && n) {
	size_t min = MIN(n, b->length - b->offset - o);
	strncpy(s, b->buf + b->offset + o, min);
	o = 0, s += min, n -= min, b = b->next;
    }
}

int buffer_chr(struct buffer *b, int c, size_t n, size_t o)
{
    size_t of = 0;

    while (b && (size_t) (b->length - b->offset) <= o) {
	o -= b->length - b->offset;
	b = b->next;
    }

    while (b && n) {
	size_t min = MIN(n, b->length - b->offset - o);
	char *t = memchr(b->buf + b->offset + o, c, min);
	if (t)
	    return (int) (of + t - b->buf - b->offset - o);
	of += min, n -= min, b = b->next, o = 0;
    }

    return -1;
}

#ifdef WITH_MMAP
struct buffer *buffer_get_mmap()
{
    struct buffer *b;

    if (mmap_freelist) {
	b = mmap_freelist;
	b->length = b->offset = 0, b->next = NULL;
	b->size = 0;
	mmap_freelist = mmap_freelist->next;
    } else
	b = Xcalloc(1, sizeof(struct buffer));

    b->mmapped = 1;
    b->buf = MAP_FAILED;
    Debug((DEBUG_BUFFER, "buffer_get_mmap = %p\n", b));
    return b;
}
#endif				/* WITH_MMAP */

struct buffer *buffer_write(struct buffer *first, char *s, size_t i)
{
    struct buffer *b, *last;
    size_t l;

    DebugIn(DEBUG_BUFFER);

    for (last = first; last && last->next; last = last->next);

    if (last == NULL || last->mmapped || last->length == last->size) {
	b = buffer_get();

	if (last)
	    last->next = b;
	else
	    first = b;
    } else
	b = last;

    l = b->size - b->length;
    if (i > l) {
	memcpy(b->buf + b->length, s, l);
	i -= l, s += l;
	b->length = b->size;
	buffer_write(b, s, i);
    } else {
	memcpy(b->buf + b->length, s, i);
	b->length += i;
    }
    DebugOut(DEBUG_BUFFER);
    return first;
}

struct buffer *buffer_printf(struct buffer *b, char *format, ...)
{
    va_list ap;
    size_t len = 1024, nlen;
    char *tmpbuf = alloca(len);

    DebugIn(DEBUG_BUFFER);

    va_start(ap, format);
    nlen = vsnprintf(tmpbuf, len, format, ap);
    va_end(ap);
    if (len <= nlen) {
	tmpbuf = alloca(++nlen);
	va_start(ap, format);
	len = vsnprintf(tmpbuf, nlen, format, ap);
	va_end(ap);
    } else
	len = nlen;

    Debug((DEBUG_BUFFER, " \"%s\"\n", tmpbuf));
    b = buffer_write(b, tmpbuf, len);

    DebugOut(DEBUG_BUFFER);
    return b;
}

struct buffer *buffer_truncate(struct buffer *b, size_t o)
{
    struct buffer *last = NULL;
    struct buffer *first = b;
    Debug((DEBUG_BUFFER, "buffer_truncate(%p, %d)\n", b, (int) o));
    while (o > 0 && b && b->length - b->offset <= o) {
	o -= b->length - b->offset;
	last = b;
	b = b->next;
    }
    if (b) {
	b->length = b->offset + o;
	b->next = buffer_free(b->next);
	if (b->length == b->offset) {
	    if (last)
		last->next = buffer_free(last->next);
	    else
		first = buffer_free(first);
	}
    }

    return first;
}

void buffer_destroy(void)
{
    while (freelist) {
	struct buffer *next = freelist->next;
	free(freelist);
	freelist = next;
    }
#ifdef WITH_MMAP
    while (mmap_freelist) {
	struct buffer *next = mmap_freelist->next;
	free(mmap_freelist);
	mmap_freelist = next;
    }
#endif				/* WITH_MMAP */
}
