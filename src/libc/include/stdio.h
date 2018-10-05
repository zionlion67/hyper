#ifndef _STDIO_H_
#define _STDIO_H_

#include <types.h>

int printf(const char *fmt, ...);
int sprintf(char *buf, const char *fmt, ...);
void puts(const char *s);
void write(const char *, u64);

#endif
