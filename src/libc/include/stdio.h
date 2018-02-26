#ifndef _STDIO_H_
#define _STDIO_H_

int printf(const char *fmt, ...);
void puts(const char *s);

#define print64(x) \
	printf("0x%x%x", (x) >> 32, (x) & 0xffffffff)

#endif
