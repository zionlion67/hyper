#include <io.h>
#include <interrupts.h>
#include <string.h>
#include <stdio.h>

void hyper_main(int magic, int info_addr)
{
	(void)magic;
	(void)info_addr;

	printf("Hello Bitz !\n");
	printf("Magic: 0x%#x\n", magic);

	init_idt();
	asm volatile ("int $0");

	char *buf = (void *)0xb8000;
	char *star = "|/-\\"; 
	for (u32 i = 0; ; i++)
		*buf = star[i++ % 4];
		

	for (;;)
		asm volatile ("hlt");
}
