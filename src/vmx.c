#include <cpuid.h>	/* compiler header */

#include <types.h>
#include <x86.h>

#ifndef __clang__
#define bit_VMX	0x20
#endif

int has_vmx_support(void)
{
	u32 eax, ebx, ecx, edx;

	/* CPUID support has already been tested in bootstrap */
	__cpuid(1, eax, ebx, ecx, edx);
	if (!(ecx & bit_VMX))
		return 0;

	u64 features = __readmsr(MSR_FEATURE_CONTROL);
	if (!(features & MSR_FEATURE_CONTROL_LOCK))
		return 0;
	if (!(features & MSR_FEATURE_CONTROL_VMXON_OUTSIDE_SMX))
		return 0;

	return 1;
}
