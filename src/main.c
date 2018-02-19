#include <compiler.h>
#include <io.h>
#include <interrupts.h>
#include <string.h>
#include <stdio.h>
#include <multiboot2.h>

static int multiboot2_valid(u32 magic, u32 info_addr)
{
	if (magic != MULTIBOOT2_BOOTLOADER_MAGIC) {
		printf("Please use a multiboot2 compliant bootloader\n");
		return 0;
	}

	if (__align(info_addr, MULTIBOOT_INFO_ALIGN) != info_addr) {
		printf("Unaligned MBI: %#x\n", info_addr);
		return 0;
	}

	return 1;
}

static void *get_multiboot_infos(u32 info_addr, u8 tag_type)
{
	struct multiboot_tag *tag = (struct multiboot_tag *)(info_addr + 8);

	while (tag->type != MULTIBOOT_TAG_TYPE_END) {
		if (tag->type == tag_type)
			return tag;
		tag = (void *)((u8 *)tag + __align_n(tag->size , 8));
	}

	return NULL;
}

void hyper_main(u32 magic, u32 info_addr)
{
	if (!multiboot2_valid(magic, info_addr))
		return;

	struct multiboot_tag_string *c = get_multiboot_infos(info_addr,
				  MULTIBOOT_TAG_TYPE_CMDLINE);
	if (c)
		printf("Commandline: %s\n", c->string);

	init_idt();
	asm volatile ("int $0");

	char *buf = (void *)0xb8000;
	char *star = "|/-\\";
	for (u32 i = 0; ; i++)
		*buf = star[i++ % 4];

	for (;;)
		asm volatile ("hlt");
}
