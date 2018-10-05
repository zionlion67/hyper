#include <printf.h>
#include <stdio.h>

void _putchar(char c)
{
	char s[2] = { c };
	write(s, 1);
}
