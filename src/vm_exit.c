#include <panic.h>
#include <vmx.h>

asm (
	".global vm_exit_stub\n\t"
	"vm_exit_stub:\n\t"
	"movq	(%rsp), %rdi\n\t"
	"movq	$0x00004402, %rax\n\t"
	"subq	$8, %rsp\n\t"
	"movq	%rsp, %rdx\n\t"
	"vmread	%rax, (%rdx)\n\t" /* VMREAD EXIT_REASON */
	"jbe	1f\n\t"
	"movq	(%rdx), %rsi\n\t"
	"movq	%rsi, %rax\n\t"
	"andq	$0xff, %rax\n\t"
	"jmp	2f\n\t"
	"1:\n\t"  /* failed VMREAD */
	"movq	$-1, %rsi\n\t"
	"callq	error_handler\n\t"
	"2:\n\t"
	"callq  *vm_exit_handlers(,%rax,8)"
);

struct vm_exit_code {
	union {
		struct {
			u16	exit_reason;
			u32	reserved1 : 11;
			u32	enclave : 1;
			u32	pending_mtf : 1;
			u32	vmx_root : 1;
			u32	reserved2 : 1;
			u32	vm_entry : 1;
		};
		u32	dword;
	};
} __packed;

typedef void (*vm_exit_handler_t)(struct vmm *vmm,
				  struct vm_exit_code exit_code);


static __used void error_handler(void)
{
	panic("VMREAD failed on VM-exit\n");
}

static const char *vm_exit_reason_str[] = {
	[0] = "Exception or NMI",
	[1] = "External Interrupt",
	[2] = "Triple Fault",
	[3] = "INIT signal",
	[4] = "SIPI",
	[5] = "IO SMI",
	[6] = "Other SMI",
	[7] = "Interrupt Window",
	[8] = "NMI Window",
	[9] = "Task switch",
	[10] = "CPUID",
	[11] = "GETSEC",
	[12] = "HLT",
	[13] = "INVD",
	[14] = "INVLPG",
	[15] = "RDPMC",
	[16] = "RDTSC",
	[17] = "RSM",
	[18] = "VMCALL",
	[19] = "VMCLEAR",
	[20] = "VMLAUNCH",
	[21] = "VMPTRLD",
	[22] = "VMPTRST",
	[23] = "VMREAD",
	[24] = "VMRESUME",
	[25] = "VMWRITE",
	[26] = "VMXOFF",
	[27] = "VMXON",
	[28] = "Control-register access",
	[29] = "MOV DR",
	[30] = "I/O instruction",
	[31] = "RDMSR",
	[32] = "WRMSR",
	[33] = "VM-entry failure due to invalid guest state",
	[34] = "VM-entry failure due to MSR loading",
	[36] = "MWAIT",
	[37] = "Monitor trap flag",
	[39] = "MONITOR",
	[40] = "PAUSE",
	[41] = "VM-entry failure due to machine-check event",
	[43] = "TPR below threshold",
	[44] = "APIC access",
	[45] = "Virtualized EOI",
	[46] = "Access to GDTR or IDTR",
	[47] = "Access to LDTR or TR",
	[48] = "EPT violation",
	[49] = "EPT misconfiguration",
	[50] = "INVEPT",
	[51] = "RDTSCP",
	[52] = "VMX-preemption timer expired",
	[53] = "INVVPID",
	[54] = "WBINVD",
	[55] = "XSETBV",
	[56] = "APIC write",
	[57] = "RDRAND",
	[58] = "INVPCID",
	[59] = "VMFUNC",
	[60] = "ENCLS",
	[61] = "RDSEED",
	[62] = "Page-modification log full",
	[63] = "XSAVE",
	[64] = "XRSTORS",
};

void default_vm_exit_handler(struct vmm *vmm __maybe_unused,
			     struct vm_exit_code exit_code __maybe_unused)
{
	u16 exit_no = exit_code.exit_reason;
	printf("reason: %s (%u)\n", vm_exit_reason_str[exit_no], exit_no);

	u64 qual;
	if (__vmread(EXIT_QUALIFICATION, &qual))
		printf("VMREAD failed\n");

	printf("qual: 0x%lx\n", qual);
	panic("");
}

#define NR_EXIT_REASONS 64
static __used vm_exit_handler_t vm_exit_handlers[NR_EXIT_REASONS] = {
	[ 0 ... NR_EXIT_REASONS - 1 ] = default_vm_exit_handler,
};
