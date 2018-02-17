#include <io.h>

void hyper_main(int magic, int info_addr)
{
	(void)magic;
	(void)info_addr;
	outb(0x3f8, 'O');
	outb(0x3f8, 'K');
	outb(0x3f8, '\n');

	char *buf = (void *)0xb8000;
	char *star = "|/-\\"; 
	for (u32 i = 0; ; i++)
		*buf = star[i++ % 4];
		

	for (;;)
		asm volatile ("hlt");
}
