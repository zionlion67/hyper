#include <string.h>

u64 strnlen(const char *s, u64 n)
{
	u64 i = 0;
	while (n-- && s[i])
		i++;
	return i;
}
