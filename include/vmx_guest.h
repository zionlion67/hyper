#ifndef _VMX_GUEST_H_
#define _VMX_GUEST_H_

struct vmm;
void setup_test_guest(struct vmm *vmm);
void setup_test_guest32(struct vmm *vmm);

#endif