#include <string.h>

void write(const char *s, u64 len);

int puts(const char *s)
{
	write(s, strlen(s));
	write("\n", 1);
	return 0;
}
