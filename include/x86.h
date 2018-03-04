#ifndef _X86_H_
#define _X86_H_

#define CR4_PAE_BIT 		5
#define CR4_PAE 		(1 << CR4_PAE_BIT)

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
		      : "g"(val)		\
		      : "memory");		\
})

#define read_cr0() __readq(cr0)
#define read_cr2() __readq(cr2)
#define read_cr3() __readq(cr3)
#define read_cr4() __readq(cr4)

#define write_cr0(x) __writeq(cr0, (x))
#define write_cr3(x) __writeq(cr3, (x))
#define write_cr4(x) __writeq(cr4, (x))

#define __readmsr(idx)				\
({						\
 	u64 __ret;				\
 	u32 __a, __d;				\
 	asm volatile ("rdmsr"			\
		      : "=d"(__d), "=a"(__a) 	\
		      : "c"(idx)		\
		      :				\
		     );				\
	__ret = (((u64)__d << 32)|((u64)__a));	\
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

#endif /* !_X86_H_ */
