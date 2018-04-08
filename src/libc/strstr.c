#include <string.h>

char *strstr(const char *haystack, const char *needle)
{
	u64 haystack_ln = strlen(haystack);
	u64 needle_ln = strlen(needle);

	for (u64 i = 0; i + needle_ln <= haystack_ln; ++i)
		if (!strncmp(haystack + i, needle, needle_ln))
			return (char *)haystack + i;
	return NULL;
}
