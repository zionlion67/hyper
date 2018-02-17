ENTRY(startup_32)

SECTIONS
{
	. = 1M;

	.text :
	{
		*(.multiboot) *(.text)
	}

	.rodata :
	{
		*(.rodata)
	}

	.data :
	{
		*(.data)
	}

	.bss :
	{
		*(.bss) *(COMMON)
	}
}
