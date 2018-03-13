#include <vmx.h>

asm (
	".global vm_exit_stub\n\t"
	"vm_exit_stub:\n\t"
	"movq	(%rsp), %rdi\n\t"
	"callq  vm_exit_handler"
);

static const char *vm_exit_reason_str[] = {
	"Exception or NMI",
	"External Interrupt",
	"Triple Fault",
	"INIT signal",
	"SIPI",
	"IO SMI",
	"Other SMI",
	"Interrupt Window",
	"NMI Window",
	"Task switch",
	"CPUID",
	"GETSEC",
	"HLT",
	"INVD",
	"INVLPG",
	"RDPMC",
	"RDTSC",
	"RSM",
	"VMCALL",
	"VMCLEAR",
	"VMLAUNCH",
	"VMPTRLD",
	"VMPTRST",
	"VMREAD",
	"VMRESUME",
	"VMWRITE",
	"VMXOFF",
	"VMXON",
	"Control-register access",
	"MOV DR",
	"I/O instruction",
	"RDMSR",
	"WRMSR",
	"VM-entry failure due to invalid guest state",
	"VM-entry failure due to MSR loading",
	"MWAIT",
	"Monitor trap flag",
	"MONITOR",
	"PAUSE",
	"VM-entry failure due to machine-check event",
	"TPR below threshold",
	"APIC access",
	"Virtualized EOI",
	"Access to GDTR or IDTR",
	"Access to LDTR or TR",
	"EPT violation",
	"EPT misconfiguration",
	"INVEPT",
	"RDTSCP",
	"VMX-preemption timer expired",
	"INVVPID",
	"WBINVD",
	"XSETBV",
	"APIC write",
	"RDRAND",
	"INVPCID",
	"VMFUNC",
	"ENCLS",
	"RDSEED",
	"Page-modification log full",
	"XSAVE",
	"XRSTORS",
};

void vm_exit_handler(struct vmm *vmm)
{
	(void)vmm;
	printf("VM EXIT\n");
	u64 exit_code;
	if (__vmread(VM_EXIT_REASON, &exit_code))
		printf("VMREAD failed\n");
	printf("reason: %s (%u)\n", vm_exit_reason_str[exit_code & 0xff], exit_code & 0xff);
	for (;;)
		asm volatile ("hlt");
	return;
}
