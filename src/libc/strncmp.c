#include <string.h>

int strncmp(const char *s1, const char *s2, u64 n)
{
	while (--n && *s1 && (*s1 == *s2)) {
		s1++;
		s2++;
	}

	return *s1 - *s2;
}
