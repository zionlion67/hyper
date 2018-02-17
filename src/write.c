#include <io.h>

void write(const char *s, u64 len)
{
	for (u64 i = 0; i < len; ++i)
		outb(0x3f8, s[i]);
}
