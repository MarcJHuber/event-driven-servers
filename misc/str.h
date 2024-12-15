#ifndef __MISC_STR_H__
#define __MISC_STR_H__

#include <stddef.h>
#include <string.h>

typedef struct {
    char *txt;
    size_t len;
} str_t;

static inline void str_set(str_t *str, char *txt, size_t len)
{
	str->txt = txt;
	str->len = len ? len : (txt ? strlen(txt) : 0);
}
#endif
