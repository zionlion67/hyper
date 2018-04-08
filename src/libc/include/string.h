#ifndef _STRING_H_
#define _STRING_H_

#include <compiler.h>
#include <types.h>

u64 strlen(const char *s);
u64 strnlen(const char *s, u64 n);

void *memset(void *s, int c, u64 n);
void *memcpy(void *dst, const void *src, u64 n);

int strcmp(const char *s1, const char *s2);
int strncmp(const char *s1, const char *s2, u64 n);

char *strstr(const char *haystack, const char *needle);

#endif
