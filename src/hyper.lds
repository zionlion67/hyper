OUTPUT_FORMAT(elf64-x86-64)

KERNEL_LMA = 2M;
KERNEL_VMA = 0xffffffff80000000 + KERNEL_LMA;

ENTRY(startup_32)

SECTIONS
{

	. = KERNEL_VMA;

	PROVIDE(_start = .);
	.text : AT(ADDR(.text) - KERNEL_VMA)
	{
		*(.multiboot) *(.text)
		. = ALIGN(0x1000);
	}

	.data : AT(ADDR(.data) - KERNEL_VMA)
	{
		*(.data)
		. = ALIGN(0x1000);
	}

	.rodata : AT(ADDR(.rodata) - KERNEL_VMA)
	{
		*(.rodata)
		. = ALIGN(0x1000);
	}

	PROVIDE(_edata = .);

	.bss : AT(ADDR(.bss) - KERNEL_VMA)
	{
		*(.bss) *(COMMON)
	}

	PROVIDE(_end = .);
}
