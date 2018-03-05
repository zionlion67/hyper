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

#endif /* !_VMX_H_ */
