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


#define __readq(reg)				\
({						\
 	u64 __ret;				\
	asm volatile ("movq %%" #reg ", %0"	\
		      : "=g"(__ret) ::); 	\
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

#endif /* !_X86_H_ */
