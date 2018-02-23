#include <string.h>

void *memset(void *s, int c, u64 n)
{
	unsigned char *p = (unsigned char *)s;
	for (u64 i = 0; i < n; ++i)
		p[i] = c;
	return p;
}
