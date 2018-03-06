#ifndef _VMX_H_
#define _VMX_H_

#include "x86.h"

#define NR_VMX_MSR 17

struct vmcs;
struct vmm {
	u64 vmx_msr[NR_VMX_MSR];

	struct vmcs *vmx_on;
	struct vmcs *vmcs;
};

int has_vmx_support(void);
int vmm_init(struct vmm *);

/*
 * Assembly magic to execute VMX instructions that
 * only take a physical address as operand.
 */
#define __vmx_insn_paddr(insn, paddr)		\
({						\
	u64 __ret;				\
	/* needed to pass expressions in paddr */ \
	u64 __paddr = (paddr);			\
	asm volatile (#insn" %[addr]\n\t"	\
		      "jbe 1f\n\t"		\
		      "mov $0, %[ret]\n\t"	\
		      "jmp 2f\n\t"		\
		      "1:\n\t"			\
		      "mov $1, %[ret]\n\t"	\
		      "2:"			\
		     : [ret] "=r"(__ret)	\
		     : [addr] "m"(__paddr)	\
		     : "cc"			\
		    );				\
	__ret;					\
})

#define __vmx_on(paddr) 	__vmx_insn_paddr(vmxon, paddr)
#define __vmx_off(paddr)	__vmx_insn_paddr(vmxoff, paddr)
#define __vmclear(paddr)	__vmx_insn_paddr(vmclear, paddr)
#define __vmptrld(paddr)	__vmx_insn_paddr(vmptrld, paddr)

#endif /* !_VMX_H_ */
