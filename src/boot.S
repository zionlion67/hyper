#include <asm.h>
#include <gdt.h>
#include <x86.h>

#define ASM_FILE
#include <multiboot2.h>

#define MULTIBOOT2_HDR_SZ 	(multiboot_header_end - multiboot_header)

#define BOOT_STACK_SZ (4 * 4096)
#define BOOT_PGTABLE_SZ (5 * 4096)

#define KERNEL_LMA 0x200000
#define KERNEL_VMA (0xffffffff80000000)

	.section .multiboot
	.type multiboot_header, @object
multiboot_header:
	.balign 8
	.long MULTIBOOT2_HEADER_MAGIC
	.long MULTIBOOT_ARCHITECTURE_I386
	.long MULTIBOOT2_HDR_SZ
	.long -(MULTIBOOT2_HEADER_MAGIC + MULTIBOOT2_HDR_SZ) // checksum

	.balign 8
	.short MULTIBOOT_HEADER_TAG_ADDRESS
	.short 0
	.long 24
	.long KERNEL_LMA // hdr physical addr
	.long KERNEL_LMA // load_addr
	.long (_edata - KERNEL_VMA) // load_end
	.long (_end - KERNEL_VMA)   // bss_end

	.balign 8
	.word MULTIBOOT_HEADER_TAG_ENTRY_ADDRESS
	.word 0
	.long 12
	.long (startup_32 - KERNEL_VMA)

	.balign 8
	// final tag
	.word MULTIBOOT_HEADER_TAG_END // type
	.word 0 // flags
	.long 8 // size
	ASM_SYM_SIZE(multiboot_header)
multiboot_header_end:

	.section .text
PROC_ENTRY(startup_32)
	.code32
	movl	$(end_stack - KERNEL_VMA), %esp
	pushl	$0
	popfl
	pushl	%ebx // save multiboot info addr
	pushl	%eax // save magic
	call	check_longmode
	testl	%eax, %eax
	jnz	.Lnolongmode

	// Enable PAE
	movl	%cr4, %eax
	orl 	$CR4_PAE, %eax
	movl	%eax, %cr4

	movl	$(boot_pgd - KERNEL_VMA), %eax
	movl	%eax, %cr3

	// Enable Long Mode in EFER
	movl	$MSR_EFER, %ecx
	rdmsr
	btsl	$MSR_EFER_LME_BIT, %eax
	wrmsr

	// Load new GDT
	lgdt	(gdtr - KERNEL_VMA)

	// Load TSS
	movl	$__TSS_ENTRY, %eax
	ltr	%ax

	pushl	$__KERNEL_CS
	pushl	$(startup_64 - KERNEL_VMA)

	// Enable Paging
	movl	$(CR0_PG | CR0_PE), %eax
	movl	%eax, %cr0

	// lret to long mode !
	lret

.Lnolongmode:
	// print KO
	movl 	$0xb8000, %esi
	movl 	$0x2f4f2f4b, (%esi)
	hlt
PROC_END(startup_32)

	.code32
#define CPUID_LM_BIT (1 << 29)
PROC_ENTRY(check_longmode)
	// CPUID detection (check if we can flip ID bit)
	pushfl
	popl 	%eax
	movl 	%eax, %ebx		// save flags
	xorl 	$0x200000, %eax		// flip ID bit
	pushl 	%eax
	popfl				// try to set EFLAGS
	pushfl
	popl 	%eax
	cmpl 	%eax, %ebx
	jz 	.Lno_longmode

	// Check for extended CPUID
	movl 	$0x80000000, %eax
	cpuid
	cmpl 	$0x80000001, %eax
	jb 	.Lno_longmode

	// Check for long mode support
	movl 	$0x80000001, %eax
	cpuid
	testl 	$CPUID_LM_BIT, %edx
	jz .Lno_longmode

	xorl 	%eax, %eax
	ret

.Lno_longmode:
	movl 	$1, %eax
	ret
PROC_END(check_longmode)

	.section .text
	.code64
PROC_ENTRY(startup_64)
	movabsq	$startup_64_high, %rax
	jmpq *%rax
PROC_END(startup_64)

PROC_ENTRY(startup_64_high)
	// Reload GDTR with GDT virtual address
	leaq	gdtr(%rip), %rax
	addq	$KERNEL_VMA, 2(%rax)
	lgdt	gdtr

	movl	$__KERNEL_DS, %eax
	movl	%eax, %ds
	movl	%eax, %es
	movl	%eax, %ss
	movl	%eax, %fs
	movl	%eax, %gs

	movl	(%esp), %edi	// multiboot2 magic
	movl	4(%esp), %esi	// multiboot2 infos addr

	//setup new stack
	movq	$end_stack, %rsp

	movq	$0x0, boot_pgd
	invlpg  0

	callq	hyper_main

	hlt
PROC_END(startup_64_high)



	.section .data
gdt:
	.quad	0x0000000000000000	/* NULL Descriptor */
	.quad	0x00af9a000000ffff	/* __KERNEL_CS */
	.quad	0x00cf92000000ffff	/* __KERNEL_DS */
	.quad	0x0080890000000000	/* TSS Descriptor */
	.quad	0x0000000000000000
gdt_end:

gdtr:
	.word	gdt_end - gdt - 1
	.long	gdt - KERNEL_VMA

.balign	4096
boot_pgd:
	.quad	boot_pud - KERNEL_VMA + 3 /* [ 0x00000000 - 0x7ffffffff ] */
	.fill	510, 8, 0
	.quad	boot_pud - KERNEL_VMA + 3 /* [ 0xfffffff800000000 - 0xffffffffffffffff ] */

boot_pud:
	.quad	boot_pmd - KERNEL_VMA + 3
	.fill	509, 8, 0
	.quad	boot_pmd - KERNEL_VMA + 3
	.fill	1, 8, 0

boot_pmd:
	.quad	0x0000000000000083	/* 0MB - 2MB */
	.quad	0x0000000000200083	/* 2MB - 4MB */

	.section .bss
stack:
	.fill BOOT_STACK_SZ, 1, 0
	.balign 16

end_stack:
