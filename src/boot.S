#include <asm.h>
#include <gdt.h>
#include <x86.h>

#define MULTIBOOT2_MAGIC 	0xe85250d6
#define MULTIBOOT2_ARCH_I386 	0x0
#define MULTIBOOT2_HDR_SZ 	(multiboot_header_end - multiboot_header)

#define BOOT_STACK_SZ (4 * 4096)
#define BOOT_PGTABLE_SZ (17 * 4096)

	.section .multiboot
	.type multiboot_header, @object
multiboot_header:
	.balign 8
	.long MULTIBOOT2_MAGIC
	.long MULTIBOOT2_ARCH_I386
	.long MULTIBOOT2_HDR_SZ
	.long -(MULTIBOOT2_MAGIC + MULTIBOOT2_HDR_SZ) // checksum
	
	// final tag
	.word 0 // type
	.word 0 // flags
	.long 8 // size
	ASM_SYM_SIZE(multiboot_header)
multiboot_header_end:

// As you might notice, the following code is basically a simplified
// linux/arch/x86/boot/compressed/head_64.S

	.section .text
PROC_ENTRY(startup_32)
	.code32
	movl	$end_stack, %esp
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

	movl	$boot_pgtable, %edi
	xorl	%eax, %eax
	movl	$(BOOT_PGTABLE_SZ/4), %ecx
	cld
	rep	stosl	// initialize all to zero

	// Level 4
	movl	$boot_pgtable, %edi
	leal	0x1007(%edi), %eax
	movl	%eax, (%edi)

	// Level 3
	movl	$boot_pgtable + 0x1000, %edi
	leal	0x1007(%edi), %eax
	movl	$4, %ecx
1:	movl	%eax, (%edi)
	addl	$0x1000, %eax
	addl	$8, %edi
	decl	%ecx
	jnz	1b

	// Level 2
	movl	$boot_pgtable + 0x2000, %edi
	movl	$0x83, %eax // P=1 U/S=1 PS=1 G=1
	movl	$2048, %ecx
1:	movl	%eax, (%edi)
	addl	$0x200000, %eax
	addl	$8, %edi
	decl	%ecx
	jnz	1b

	// We are identity mapped for the first 4GB of RAM
	movl	$boot_pgtable, %eax
	movl	%eax, %cr3

	// Enable Long Mode in EFER
	movl	$MSR_EFER, %ecx
	rdmsr
	btsl	$MSR_EFER_LME_BIT, %eax
	wrmsr

	// Load new GDT
	lgdt	gdtr

	// Load TSS
	movl	$__TSS_ENTRY, %eax
	ltr	%ax

	pushl	$__KERNEL_CS
	pushl	$startup_64

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

	.code64
PROC_ENTRY(startup_64)
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

	callq	hyper_main

	hlt
PROC_END(startup_64)

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


	.section .data
gdt:
	.quad	0x0000000000000000	/* NULL Descriptor */
	.quad	0x00af9a000000ffff	/* __KERNEL_CS */
	.quad	0x00cf92000000ffff	/* __KERNEL_DS */
	.quad	0x0080890000000000	/* TSS Descriptor */
	.quad	0x0000000000000000
gdt_end:

gdtr:
	.word	gdt_end - gdt
	.long	gdt

	.section .bss
stack:
	.fill BOOT_STACK_SZ, 1, 0
	.balign 16

.global end_stack
end_stack:

.global boot_pgtable
boot_pgtable:
	.balign 0x1000
	.fill BOOT_PGTABLE_SZ, 1, 0
