#ifndef _X86_H_
#define _X86_H_

#define CR4_PAE_BIT 		5
#define CR4_VMXE_BIT		13

#define CR4_PAE 		(1 << CR4_PAE_BIT)
#define CR4_VMXE		(1 << CR4_VMXE_BIT)

#define CR0_PE_BIT		0
#define CR0_PG_BIT		31

#define CR0_PE			(1 << CR0_PE_BIT)
#define CR0_PG			(1 << CR0_PG_BIT)

#define MSR_EFER		0xc0000080 /* Extended Features Register */
#define MSR_EFER_LME_BIT	8
#define MSR_EFER_LME		(1 << MSR_EFER_LME_BIT)

#define MSR_FEATURE_CONTROL			0x003a
#define MSR_FEATURE_CONTROL_LOCK		0x0001
#define MSR_FEATURE_CONTROL_VMXON_OUTSIDE_SMX	0x0004

#define MSR_SYSENTER_CS		0x174
#define MSR_SYSENTER_ESP	0x175
#define MSR_SYSENTER_EIP	0x176

#define MSR_PAT			0x277
#define MSR_PERF_GLOBAL_CTRL	0x38f
#define MSR_FS_BASE		0xc0000100
#define MSR_GS_BASE		0xc0000101

#define MSR_VMX_BASIC		0x480
#define MSR_VMX_PIN_CTLS	0x481
#define MSR_VMX_PROC_CTLS	0x482
#define MSR_VMX_EXIT_CTLS	0x483
#define MSR_VMX_ENTRY_CTLS	0x484
#define MSR_VMX_MISC		0x485
#define MSR_VMX_CR0_FIXED0	0x486
#define MSR_VMX_CR0_FIXED1	0x487
#define MSR_VMX_CR4_FIXED0	0x488
#define MSR_VMX_CR4_FIXED1	0x489
#define MSR_VMX_VMCS_ENUM	0x48a
#define MSR_VMX_PROC_CTLS2	0x48b
#define MSR_VMX_EPT_VPID_CAP	0x48c
#define MSR_VMX_TRUE_PIN_CTLS	0x48d
#define MSR_VMX_TRUE_PROC_CTLS	0x48e
#define MSR_VMX_TRUE_EXIT_CTLS	0x48f
#define MSR_VMX_TRUE_ENTRY_CTLS 0x490
#define MSR_VMX_VMFUNC		0x491

#ifndef __ASM__
#include <gdt.h>
#define __readq(reg)				\
({						\
 	u64 __ret;				\
	asm volatile ("movq %%" #reg ", %0"	\
		      : "=r"(__ret) ::); 	\
	__ret;					\
})

#define __writeq(reg, val)			\
({						\
	asm volatile ("movq %0, %%" #reg	\
		      : /* No output */		\
		      : "r"(val)		\
		      : "memory");		\
})

#define __readw(reg)				\
({						\
 	u16 __ret;				\
	asm volatile ("movw %%" #reg ", %0"	\
		      : "=r"(__ret) ::); 	\
	__ret;					\
})


#define read_cr0() 	__readq(cr0)
#define read_cr2() 	__readq(cr2)
#define read_cr3() 	__readq(cr3)
#define read_cr4() 	__readq(cr4)

#define read_cs() 	__readw(cs)
#define read_ds() 	__readw(ds)
#define read_es() 	__readw(es)
#define read_ss() 	__readw(ss)
#define read_fs() 	__readw(fs)
#define read_gs() 	__readw(gs)

#define read_rsp()	__readq(rsp)

/* TODO static inline write to reg wrapper */
#define write_cr0(x)	__writeq(cr0, (x))
#define write_cr3(x) 	__writeq(cr3, (x))
#define write_cr4(x) 	__writeq(cr4, (x))


#define EAX_EDX_VAL(low, high) ((low) | (high) << 32)

#define __readmsr(idx)				\
({						\
 	u64 __ret;				\
 	u64 __a, __d;				\
 	asm volatile ("rdmsr"			\
		      : "=d"(__d), "=a"(__a) 	\
		      : "c"(idx)		\
		      :				\
		     );				\
	__ret = EAX_EDX_VAL(__a, __d);		\
	__ret;					\
})

#define __writemsr(idx, val)			\
do {						\
	asm volatile ("wrmsr"			\
		      : /* No outputs */	\
		      : "c"(idx), "d"(val >> 32), "a"(val)	\
		      :				\
		     );				\
} while (0)

static inline void __sidt(struct gdtr *gdtr)
{
	asm volatile ("sidt %0" : : "m"(*gdtr));
}

static inline void __sgdt(struct gdtr *gdtr)
{
	asm volatile ("sgdt %0" : : "m"(*gdtr));
}

static inline u16 __str(void)
{
	u16 ret;
	asm volatile ("strw %w0" : "=r"(ret));
	return ret;
}

#endif /* !__ASM__ */
#endif /* !_X86_H_ */
