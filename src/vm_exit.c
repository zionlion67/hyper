#include <cpuid.h>

#include <io.h>
#include <interrupts.h>
#include <page.h>
#include <panic.h>
#include <vmx.h>

asm (
	".global vm_exit_stub\n\t"
	"vm_exit_stub:\n\t"
	"subq	$16, %rsp\n\t"
	PUSH_ALL_REGS_STR
	"movq	0xa0(%rsp), %rdi\n\t"
	"movq	%rsp, %rsi\n\t"
	"callq	vm_exit_dispatch\n\t"
	POP_ALL_REGS_STR
	"addq	$16, %rsp\n\t"
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

#ifdef DEBUG
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
#endif

static void dump_vm_exit_ctx(struct vm_exit_ctx *ctx)
{
	printf("Guest registers:\n");
	dump_x86_regs(&ctx->regs);

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
	printf("EPT Error code: ");

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

	printf("\n");
	dump_vm_exit_ctx(ctx);

	printf("Guest linear addr: 0x%lx\n", guest_addr);
	__vmread(GUEST_PHYSICAL_ADDRESS, &guest_addr);
	printf("Guest physical addr: 0x%lx\n", guest_addr);
	paddr_t host_paddr = ept_translate(vmm, guest_addr);
	printf("Host physical addr: 0x%x%x\n",
		host_paddr >> 32, host_paddr & 0xffffffff);
	panic("");
}


static inline void set_ctx_cpuid(struct vm_exit_ctx *ctx, u64 eax, u64 ebx,
				 u64 ecx, u64 edx)
{
	ctx->regs.rax = eax;
	ctx->regs.rbx = ebx;
	ctx->regs.rcx = ecx;
	ctx->regs.rdx = edx;
}

/* cpuid[1].edx */
#define NEED_FPU	(1 << 0)
#define NEED_VME	(1 << 1)
#define NEED_DE		(1 << 2)
#define NEED_PSE	(1 << 3)
#define NEED_TSC	(1 << 4)
#define NEED_MSR	(1 << 5)
#define NEED_PAE	(1 << 6)
#define NEED_MCE	(1 << 7)
#define NEED_CX8	(1 << 8)
#define NEED_APIC	(1 << 9)
#define NEED_SEP	(1 << 11)
#define NEED_PGE	(1 << 13)
#define NEED_MCA	(1 << 14)
#define NEED_CMOV	(1 << 15)
#define NEED_PAT	(1 << 16)
#define NEED_PSE36	(1 << 17)
#define NEED_PSN	(1 << 18)
#define NEED_CLFSH	(1 << 19)
#define NEED_DS		(1 << 21)
#define NEED_ACPI	(1 << 22)
#define NEED_MMX	(1 << 23)
#define NEED_FXSR	(1 << 24)
#define NEED_SSE	(1 << 25)
#define NEED_SSE2	(1 << 26)
#define NEED_XMM	NEED_SSE
#define NEED_XMM2	NEED_SSE2
#define NEED_SS		(1 << 27)
#define NEED_HTT	(1 << 28)
#define NEED_TM		(1 << 29)
#define NEED_PBE	(1 << 31)

#define NEED_LM		(1 << 29)
#define NEED_3DNOW	(1 << 31)

/* Minimum to make 64bits linux happy */
#define CPUID_1_EAX	0
#define CPUID_1_EBX	0
#define CPUID_1_ECX	0
#define CPUID_1_EDX	(NEED_FPU|NEED_PSE|NEED_MSR|NEED_PAE|\
			 NEED_CX8|NEED_PGE|NEED_FXSR|NEED_CMOV|\
			 NEED_XMM|NEED_XMM2)

static void cpuid_exit_handler(struct vmm *vmm __unused, struct vm_exit_ctx *ctx)
{
	const char signature[] = "BitzDuLSE!\0\0";
	const u32 *sig_ptr = (const u32 *)signature;
	u64 sig1 = (u64)sig_ptr[0];
	u64 sig2 = (u64)sig_ptr[2];
	u64 sig3 = (u64)sig_ptr[1];

	switch (ctx->regs.rax) {
	case 0:
		set_ctx_cpuid(ctx, 1, sig1, sig2, sig3);
		break;
	case 1:
		set_ctx_cpuid(ctx, CPUID_1_EAX, CPUID_1_EBX, CPUID_1_ECX,
			      CPUID_1_EDX);
		break;
	/* Extended CPUIDs */
	case 0x80000000:
		set_ctx_cpuid(ctx, 0x80000001, 0, 0, 0);
		break;
	case 0x80000001:
		set_ctx_cpuid(ctx, 0, 0, 0, NEED_LM|NEED_3DNOW);
		break;
	default:
		panic("CPUID eax not implemented yet\n");
		break;
	}
}

#define INTR_EXTERNAL		0
#define INTR_NMI		2
#define INTR_HW_EXCEPTION	3
#define INTR_SOFT		4
#define INTR_PRIV_EXCEPTION	5
#define	INTR_SOFT_EXCEPTION	6
struct idt_vector_info {
	union {
		struct {
			u32	vec : 8;
			u32	type : 3;
			u32	code_valid : 1;
			u32	reserved : 19;
			u32	valid : 1;

		};
		u32	dword;
	};
} __packed;

static void exception_handler(struct vmm *vmm, struct vm_exit_ctx *ctx)
{
	u64 val;
	__vmread(VM_EXIT_INTR_INFO, &val);

	struct idt_vector_info info_vec = {
		.dword = val & 0xffffffff,
	};
	printf("Exception: %s (valid=%u)\n", exception_str(info_vec.vec),
					     info_vec.valid);

	if (info_vec.code_valid) {
		__vmread(VM_EXIT_INTR_ERROR_CODE, &val);
		printf("Error code: 0x%x%x\n", val >> 32, val & 0xffffffff);
	}

	dump_vm_exit_ctx(ctx);
	dump_guest_state(&vmm->guest_state);

	u64 cr2 = read_cr2();
	printf("CR2: 0x%x%x\n", cr2 >> 32, cr2 & 0xfffffffff);

	panic("");
}

#define ACCESS_TYPE_MOV_TO_CR	0	
#define ACCESS_TYPE_MOV_FROM_CR	1
#define ACCESS_TYPE_CLTS	2
#define ACCESS_TYPE_LMSW	3
struct cr_access_info {
	union {
		struct {
			u64	num : 4;
			u64	access_type : 2;
			u64	lmsw_op_type : 1;
			u64	reserved1 : 1;
			u64	source_op : 4;
			u64	reserved2 : 4;
			u64	lmsw_source : 16;
			u64	reserved3 : 32;
		};
		u64	quad_word;
	};
} __packed;

static u64 *get_operand_reg(struct vm_exit_ctx *ctx, u8 num)
{
	switch (num) {
	case 0:
		return &ctx->regs.rax;
	case 1:
		return &ctx->regs.rcx;
	case 2:
		return &ctx->regs.rdx;
	case 3:
		return &ctx->regs.rbx;
	case 4:
		return &ctx->regs.rsp;
	case 5:
		return &ctx->regs.rbp;
	case 6:
		return &ctx->regs.rsi;
	case 7:
		return &ctx->regs.rdi;
	case 8 ... 15:
		return (&ctx->regs.r8) + num - 8;
	default:
		panic("Cannot determine MOV TO CR source operand\n");
	}
}

static void reload_pdpte(struct vmm *vmm)
{
	u64 cr3 = vmm->guest_state.reg_state.control_regs.cr3 & PAGE_MASK;
	u64 *pdpte = (u64 *)gpa_to_hva(vmm, cr3);

	for (u8 i = 0; i < 4; ++i) {
		vmm->guest_state.pdpte[i] = pdpte[i];
		__vmwrite(GUEST_PDPTE0 + i * 2, pdpte[i]);
	}
}

/* TODO REMOVE MOV TO CR3 LOAD EXIT VM ENTRY CONTROL */
static void set_guest_long_mode(struct vmm *vmm)
{
	struct vmcs_guest_register_state *state = &vmm->guest_state.reg_state;
	state->msr.ia32_efer |= MSR_EFER_LMA;

	__vmwrite(GUEST_EFER, state->msr.ia32_efer);

	u64 vm_entry_ctl;
	__vmread(VM_ENTRY_CONTROLS, &vm_entry_ctl);
	vm_entry_ctl |= VM_ENTRY_IA32E_GUEST;
	__vmwrite(VM_ENTRY_CONTROLS, vm_entry_ctl);
}

static inline int turn_on_paging(u64 *new_cr0, u64 *cr0)
{
	return !(*cr0 & CR0_PG) && (*new_cr0 & CR0_PG);
}

static inline void cr_access_cr0(struct vmm *vmm, u64 *new_cr0)
{
	struct vmcs_guest_register_state *state = &vmm->guest_state.reg_state;
	u64 *cr0 = &state->control_regs.cr0;

	if (turn_on_paging(new_cr0, cr0) && state->msr.ia32_efer & MSR_EFER_LME)
		set_guest_long_mode(vmm);

	*cr0 |= *new_cr0;

	__vmwrite(GUEST_CR0, *cr0);
	__vmwrite(CR0_READ_SHADOW, *cr0);
}

static void cr_access_cr3(struct vmm *vmm, u64 *reg)
{
	struct vmcs_guest_register_state *state = &vmm->guest_state.reg_state;
	u64 *cr3 = &state->control_regs.cr3;
	*cr3 = *reg;

	u64 long_mode_active = (state->msr.ia32_efer >> MSR_EFER_LMA_BIT) & 1;

	if ((state->control_regs.cr4 & CR4_PAE) && !long_mode_active)
		reload_pdpte(vmm);

	__vmwrite(GUEST_CR3, *cr3);
}

static void cr_access_cr4(struct vmm *vmm, u64 *reg)
{
	u64 *cr4 = &vmm->guest_state.reg_state.control_regs.cr4;
	*cr4 |= *reg;

	__vmwrite(GUEST_CR4, *cr4);
	__vmwrite(CR4_READ_SHADOW, *cr4);
}

static void cr_access_handler(struct vmm *vmm, struct vm_exit_ctx *ctx)
{
	struct cr_access_info cr_info = {
		.quad_word = ctx->exit_qual,
	};

	if (cr_info.access_type != 0)
		panic("Unimplemented MOV CR access type\n");

	u64 *reg = get_operand_reg(ctx, cr_info.source_op);

	if (cr_info.num == 0) {
		cr_access_cr0(vmm, reg);
	} else if (cr_info.num == 3) {
		cr_access_cr3(vmm, reg);
	} else if (cr_info.num == 4) {
		cr_access_cr4(vmm, reg);
	} else {
		panic("Unimplemnted MOV TO CR\n");
	}
}

struct io_access_info {
	union {
		struct {
			u64	access_sz : 3;
			u64	in        : 1;
			u64	string    : 1;
			u64	rep_insn  : 1;
			u64	imm_op    : 1;
			u64	res1      : 9;
			u64	port      : 16;
			u64	res2      : 32;
		};
		u64	quad_word;
	};
} __packed;

#ifdef IO_DEBUG
static void log_io_access(struct io_access_info *info)
{
	printf("I/O access: ");

	const char *rep = info->rep_insn ? "rep" : "";
	const char *insn = info->in ? "in" : "out";
	char size[3] = { 0, 0, 0, };
	u8 size_idx = 0;

	if (info->string)
		size[size_idx++] = 's';
	if (info->access_sz == 0)
		size[size_idx] = 'b';
	if (info->access_sz == 1)
		size[size_idx] = 'w';
	if (info->access_sz == 3)
		size[size_idx]= 'l';

	printf("%s %s%s 0x%x\n", rep, insn, size, info->port);
}
#else
static void log_io_access(struct io_access_info *info __unused) {}
#endif

/* TODO remove magix */
static inline int is_serial_access(const u16 port)
{
	return 0x3f8 <= port && port <= 0x3ff;
}

static inline int is_pic_access(const u16 port)
{
	return port == 0x20 || port == 0x21 || port == 0xa0 || port == 0xa1;
}

static inline int is_kbd_access(const u16 port)
{
	return port == 0x64 || port == 0x60;
}

static inline int is_pit_access(const u16 port)
{
	/* Only passthrough timer */
	return port == 0x40;
}

static void io_access_handler(struct vmm *vmm __unused, struct vm_exit_ctx *ctx)
{
	struct io_access_info info = {
		.quad_word = ctx->exit_qual,
	};

	const u16 port = info.port;

	if (!is_serial_access(port) && !is_pic_access(port)
	    && !is_kbd_access(port) && !is_pit_access(port)) {
		log_io_access(&info);
		return;
	}

	if (info.string || info.rep_insn)
		panic("Unhandled I/O string instruction\n");

	if (!info.in) {
		if (info.access_sz == 0) {
			/* Hack to print on serial + VGA text */
			if (port == 0x3f8) {
				printf("%c", ctx->regs.rax & 0xff);
				return;
			}
			outb(port, ctx->regs.rax & 0xff);
		} else if (info.access_sz == 1) {
			outw(port, ctx->regs.rax & 0xffff);
		} else {
			outl(port, ctx->regs.rax & 0xffffffff);
		}
	} else {
		if (info.access_sz == 0)
			ctx->regs.rax = inb(port);
		else if (info.access_sz == 1)
			ctx->regs.rax = inw(port);
		else
			ctx->regs.rax = inl(port);
	}
}

static inline void read_guest_control_regs(struct control_regs *regs)
{
	__vmread(GUEST_CR0, &regs->cr0);
	__vmread(GUEST_CR3, &regs->cr3);
	__vmread(GUEST_CR4, &regs->cr4);
}

#define READ_SEG_DESC(segs, Desc, desc) 				\
	do {								\
		__vmread(GUEST_##Desc##_SELECTOR, &segs->desc.selector); \
		__vmread(GUEST_##Desc##_BASE, &segs->desc.base);	\
		__vmread(GUEST_##Desc##_LIMIT, &segs->desc.limit);	\
		__vmread(GUEST_##Desc##_AR_BYTES, &segs->desc.access);	\
	} while (0)

static void read_guest_seg_descs(struct segment_descriptors *segs)
{
	READ_SEG_DESC(segs, CS, cs);
	READ_SEG_DESC(segs, DS, ds);
	READ_SEG_DESC(segs, ES, es);
	READ_SEG_DESC(segs, SS, ss);
	READ_SEG_DESC(segs, FS, fs);
	READ_SEG_DESC(segs, GS, gs);
	READ_SEG_DESC(segs, TR, tr);
	READ_SEG_DESC(segs, LDTR, ldtr);
}

static void read_guest_table_regs(struct vmcs_guest_register_state *state)
{
	__vmread(GUEST_GDTR_BASE, &state->gdtr.base);
	__vmread(GUEST_IDTR_BASE, &state->idtr.base);
	__vmread(GUEST_GDTR_LIMIT, &state->gdtr.limit);
	__vmread(GUEST_IDTR_LIMIT, &state->idtr.limit);
}

static void read_guest_msrs(struct vmcs_state_msr *msr)
{
	__vmread(GUEST_SYSENTER_CS, &msr->ia32_sysenter_cs);
	__vmread(GUEST_SYSENTER_ESP, &msr->ia32_sysenter_esp);
	__vmread(GUEST_SYSENTER_EIP, &msr->ia32_sysenter_eip);
	__vmread(GUEST_PAT, &msr->ia32_pat);
	__vmread(GUEST_EFER, &msr->ia32_efer);
	__vmread(GUEST_BNDCFGS, &msr->ia32_bndcfgs);
	__vmread(GUEST_DEBUGCTL, &msr->ia32_debugctl);
	__vmread(GUEST_PERF_GLOBAL_CTRL, &msr->ia32_perf_global_ctrl);
}

static void read_guest_reg_state(struct vmcs_guest_register_state *state)
{
	read_guest_control_regs(&state->control_regs);
	read_guest_seg_descs(&state->seg_descs);
	read_guest_table_regs(state);
	read_guest_msrs(&state->msr);
}

static void read_guest_state(struct vmm *vmm)
{
	struct vmcs_guest_state *guest_state = &vmm->guest_state;
	read_guest_reg_state(&guest_state->reg_state);

	for (u8 i = 0; i < 4; ++i) {
		__vmread(GUEST_PDPTE0 + i * 2, &guest_state->pdpte[i]);
	}
}

static void __used vm_exit_dispatch(struct vmm *vmm, struct vm_exit_ctx *ctx)
{
#ifdef DEBUG
	printf("\nVM EXIT ");
#endif

	__vmread(VM_EXIT_REASON, &ctx->exit_code);
	__vmread(EXIT_QUALIFICATION, &ctx->exit_qual);

#ifdef DEBUG
	u16 exit_no = ctx->exit_code.exit_reason;
	printf("Reason: %s (%u)\n", vm_exit_reason_str[exit_no], exit_no);
#endif

	__vmread(GUEST_RIP, &ctx->regs.rip);
	__vmread(GUEST_RSP, &ctx->regs.rsp);
	__vmread(GUEST_RFLAGS, &ctx->regs.rflags);

	read_guest_state(vmm);

	/* Handlers must not modify guest RIP */
	vm_exit_handlers[ctx->exit_code.dword](vmm, ctx);

	u64 insn_len;
	__vmread(VM_EXIT_INSTRUCTION_LEN, &insn_len);
	ctx->regs.rip += insn_len;
	__vmwrite(GUEST_RIP, ctx->regs.rip);
}

#define INTR_OR_NMI_EXIT_NO	0
#define CPUID_EXIT_NO		10
#define MOV_CR_EXIT_NO		28
#define IO_EXIT_NO		30
#define EPT_VIOLATION_EXIT_NO	48
int init_vm_exit_handlers(struct vmm *vmm __maybe_unused)
{
	add_vm_exit_handler(INTR_OR_NMI_EXIT_NO, exception_handler);
	add_vm_exit_handler(CPUID_EXIT_NO, cpuid_exit_handler);
	add_vm_exit_handler(MOV_CR_EXIT_NO, cr_access_handler);
	add_vm_exit_handler(IO_EXIT_NO, io_access_handler);
	add_vm_exit_handler(EPT_VIOLATION_EXIT_NO, ept_violation_handler);
	return 0;
}
