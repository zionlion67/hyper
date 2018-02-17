#include <string.h>

u64 strlen(const char *s)
{
	u64 i = 0;
	while (s[i])
		i++;
	return i;
}
