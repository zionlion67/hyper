#include <panic.h>
#include <vmx.h>

asm (
	".global vm_exit_stub\n\t"
	"vm_exit_stub:\n\t"
	PUSH_ALL_REGS_STR
	"movq	0x90(%rsp), %rdi\n\t"
	"movq	%rsp, %rsi\n\t"
	"callq	vm_exit_dispatch\n\t"
	POP_ALL_REGS_STR
	"vmresume\n\t"
	"jbe error_handler\n\t"
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

struct vm_exit_ctx {
	struct x86_regs 	regs;
	u64			exit_qual;
	struct vm_exit_code 	exit_code;
} __packed;

typedef void (*vm_exit_handler_t)(struct vmm *vmm,
				  struct vm_exit_ctx *ctx);

static __used void error_handler(void)
{
	panic("VMRESUME failed...");
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

static void dump_vm_exit_ctx(struct vm_exit_ctx *ctx)
{
	printf("Guest registers:\n");
	dump_x86_regs(&ctx->regs);

	u16 exit_no = ctx->exit_code.exit_reason;
	printf("reason: %s (%u)\n", vm_exit_reason_str[exit_no], exit_no);
	printf("qual: 0x%lx\n", ctx->exit_qual);

}

static void default_vm_exit_handler(struct vmm *vmm __maybe_unused,
				    struct vm_exit_ctx *ctx)
{
	dump_vm_exit_ctx(ctx);
	panic("");
}

#define NR_EXIT_REASONS 64
static __used vm_exit_handler_t vm_exit_handlers[NR_EXIT_REASONS] = {
	[ 0 ... NR_EXIT_REASONS - 1 ] = default_vm_exit_handler,
};

static int add_vm_exit_handler(const u32 n, vm_exit_handler_t handler)
{
	if (n >= NR_EXIT_REASONS)
		return 1;
	vm_exit_handlers[n] = handler;
	return 0;
}

/* Dummy handler that just pretty prints the error code */
static void ept_violation_handler(struct vmm *vmm __maybe_unused,
				  struct vm_exit_ctx *ctx)
{
	u64 qual = ctx->exit_qual;
	printf("EPT Error code: ", qual);

	u64 guest_addr = (u64)-1;

	int printed = 0;
#define X(Str) printed = printf("%s"#Str, printed ? "|" : "")
	if (qual & (1 << 0))
		X(READ);
	if (qual & (1 << 1))
		X(WRITE);
	if (qual & (1 << 2))
		X(EXEC);
	if (qual & (1 << 7)) {
		__vmread(GUEST_LINEAR_ADDRESS, &guest_addr);
		if (qual & (1 << 8))
			X(EPT_LINEAR);
		else
			X(EPT_PAGING_ENTRY);
	}
#undef X

	dump_vm_exit_ctx(ctx);
	
	printf("Guest linear addr: 0x%lx\n", guest_addr);
	__vmread(GUEST_PHYSICAL_ADDRESS, &guest_addr);
	printf("Guest physical addr: 0x%lx\n", guest_addr);
	paddr_t host_paddr = ept_translate(&vmm->eptp, guest_addr);
	printf("Host physical addr: 0x%x%x\n",
		host_paddr >> 32, host_paddr & 0xffffffff);
	panic("");
}

#define EPT_VIOLATION_EXIT_NO	48
int init_vm_exit_handlers(struct vmm *vmm __maybe_unused)
{
	add_vm_exit_handler(EPT_VIOLATION_EXIT_NO, ept_violation_handler);
	return 0;
}

static void __used vm_exit_dispatch(struct vmm *vmm, struct vm_exit_ctx *ctx)
{
	printf("VM EXIT\n");

	__vmread(VM_EXIT_REASON, &ctx->exit_code);
	__vmread(EXIT_QUALIFICATION, &ctx->exit_qual);

	__vmread(GUEST_RIP, &ctx->regs.rip);
	__vmread(GUEST_RSP, &ctx->regs.rsp);
	__vmread(GUEST_RFLAGS, &ctx->regs.rflags);

	/* Handlers must not modify guest RIP */
	vm_exit_handlers[ctx->exit_code.dword](vmm, ctx);

	u64 insn_len;
	__vmread(VM_EXIT_INSTRUCTION_LEN, &insn_len);
	ctx->regs.rip += insn_len;
	__vmwrite(GUEST_RIP, ctx->regs.rip);
}
