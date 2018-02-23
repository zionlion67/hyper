#ifndef _STRLEN_H_
#define _STRLEN_H_

#include <types.h>

u64 strlen(const char *s);
u64 strnlen(const char *s, u64 n);

void *memset(void *s, int c, u64 n);

#endif
