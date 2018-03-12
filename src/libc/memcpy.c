#include <string.h>

void *memcpy(void *dest, const void *src, u64 n)
{
	u8 *d = dest;
	const u8 *s = src;
	for (u64 i = 0; i < n; ++i)
		d[i] = s[i];
	return dest;
}
