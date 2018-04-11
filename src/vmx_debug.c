#include <vmx.h>

static void dump_control_regs(struct control_regs *regs)
{
	printf("Control registers:\n");
	printf("CR0: 0x%lx\n", regs->cr0);
	printf("CR3: 0x%lx\n", regs->cr3);
	printf("CR4: 0x%lx\n\n", regs->cr4);
}

static void dump_seg_desc(struct segment_descriptor *desc, const char *name)
{
	printf("%s:\tSel: 0x%lx\tBase: 0x%lx\tLimit: 0x%x\n", name,
	       desc->selector, desc->base, desc->limit);
	printf("%s:\ttype: 0x%x\ts: 0x%x\tdpl: 0x%x\tp: %u avl: 0x%x\tl: %u\t"
	       "db: %u\tg: %u\tunusable: %u\n\n", name, desc->type, desc->s,
	       desc->dpl, desc->p, desc->avl, desc->l, desc->db, desc->g,
	       desc->unusable);
}

static void dump_table_register(struct table_register *reg, const char *name)
{
	printf("%s:\nBase: 0x%lx\tLimit: 0x%x\n", name, reg->base, reg->limit);
}

static void dump_guest_register_state(struct vmcs_guest_register_state *state)
{
	dump_control_regs(&state->control_regs);

	printf("Segment descriptors:\n");
#define X(sel) dump_seg_desc(&state->seg_descs.sel, #sel)
	X(cs);
	X(ds);
	X(es);
	X(ss);
	X(fs);
	X(gs);
	X(tr);
	X(ldtr);
#undef X

	dump_table_register(&state->gdtr, "GDTR");
	dump_table_register(&state->idtr, "IDTR");
	printf("\n");

	printf("MSRs:\n");
#define X(Msr) printf("ia32_%s:\t0x%lx\n", #Msr, state->msr.ia32_##Msr)
	X(sysenter_cs);
	X(fs_base);
	X(gs_base);
	X(sysenter_esp);
	X(sysenter_eip);
	X(perf_global_ctrl);
	X(pat);
	X(efer);
	X(debugctl);
	X(bndcfgs);
#undef X
	printf("\n");

	printf("DR7:\t0x%lx\n", state->dr7);
	printf("RFLAGS:\t0x%lx\n", state->regs.rflags);
	printf("RSP:\t0x%lx\n", state->regs.rsp);
	printf("RIP:\t0x%lx\n", state->regs.rip);
	printf("\n");

}

void dump_guest_state(struct vmcs_guest_state *state)
{
	printf("Dumping guest state:\n");
	dump_guest_register_state(&state->reg_state);

	printf("Non-register state:\n");
#define X(field) printf("%s:\t0x%lx\n", #field, state->field)
	X(intr_state);
	X(activity_state);
	X(preempt_timer);
	X(intr_status);
	X(pml_index);
	X(vmcs_link);
	X(pdpte[0]);
	X(pdpte[1]);
	X(pdpte[2]);
	X(pdpte[3]);
#undef X
	return;
}

struct vmcs_field_str {
	enum vmcs_field field;
	const char *str;
};

/* Only fields that are used atm */
static const struct vmcs_field_str vmcs_field_str_array[] = {
	{ GUEST_ES_SELECTOR, 		"GUEST_ES_SELECTOR" },
	{ GUEST_CS_SELECTOR,		"GUEST_CS_SELECTOR" },
	{ GUEST_SS_SELECTOR,		"GUEST_SS_SELECTOR" },
	{ GUEST_DS_SELECTOR,		"GUEST_DS_SELECTOR" },
	{ GUEST_FS_SELECTOR,		"GUEST_FS_SELECTOR" },
	{ GUEST_GS_SELECTOR,		"GUEST_GS_SELECTOR" },
	{ GUEST_LDTR_SELECTOR,		"GUEST_LDTR_SELECTOR" },
	{ GUEST_TR_SELECTOR,		"GUEST_TR_SELECTOR" },

	{ HOST_ES_SELECTOR, 		"HOST_ES_SELECTOR" },
	{ HOST_CS_SELECTOR,		"HOST_CS_SELECTOR" },
	{ HOST_SS_SELECTOR,		"HOST_SS_SELECTOR" },
	{ HOST_DS_SELECTOR,		"HOST_DS_SELECTOR" },
	{ HOST_FS_SELECTOR,		"HOST_FS_SELECTOR" },
	{ HOST_GS_SELECTOR,		"HOST_GS_SELECTOR" },
	{ HOST_TR_SELECTOR,		"HOST_TR_SELECTOR" },

	{ EPT_POINTER,			"EPT_POINTER" },
	{ VMCS_LINK_POINTER,		"VMCS_LINK_POINTER" },

	{ GUEST_DEBUGCTL,		"GUEST_DEBUGCTL" },
	{ GUEST_PAT,			"GUEST_PAT" },
	{ GUEST_EFER,			"GUEST_EFER" },
	{ GUEST_PERF_GLOBAL_CTRL, 	"GUEST_PERF_GLOBAL_CTRL" },
	{ GUEST_BNDCFGS,		"GUEST_BNDCFGS" },

	{ HOST_PAT,			"HOST_PAT" },
	{ HOST_EFER,			"HOST_EFER" },
	{ HOST_PERF_GLOBAL_CTRL, 	"HOST_PERF_GLOBAL_CTRL" },

	{ PIN_BASED_VM_EXEC_CONTROL,	"PIN_BASED_VM_EXEC_CONTROL" },
	{ CPU_BASED_VM_EXEC_CONTROL,	"CPU_BASED_VM_EXEC_CONTROL" },
	{ EXCEPTION_BITMAP,		"EXCEPTION_BITMAP" },

	{ VM_EXIT_CONTROLS,		"VM_EXIT_CONTROLS" },
	{ VM_ENTRY_CONTROLS,		"VM_ENTRY_CONTROLS" },

	{ SECONDARY_VM_EXEC_CONTROL,	"SECONDARY_VM_EXEC_CONTROL" },

	{ GUEST_ES_LIMIT, 		"GUEST_ES_LIMIT" },
	{ GUEST_CS_LIMIT,		"GUEST_CS_LIMIT" },
	{ GUEST_SS_LIMIT,		"GUEST_SS_LIMIT" },
	{ GUEST_DS_LIMIT,		"GUEST_DS_LIMIT" },
	{ GUEST_FS_LIMIT,		"GUEST_FS_LIMIT" },
	{ GUEST_GS_LIMIT,		"GUEST_GS_LIMIT" },
	{ GUEST_LDTR_LIMIT,		"GUEST_LDTR_LIMIT" },
	{ GUEST_TR_LIMIT,		"GUEST_TR_LIMIT" },

	{ GUEST_GDTR_LIMIT,		"GUEST_GDTR_LIMIT" },
	{ GUEST_IDTR_LIMIT,		"GUEST_IDTR_LIMIT" },

	{ GUEST_ES_AR_BYTES, 		"GUEST_ES_AR_BYTES" },
	{ GUEST_CS_AR_BYTES,		"GUEST_CS_AR_BYTES" },
	{ GUEST_SS_AR_BYTES,		"GUEST_SS_AR_BYTES" },
	{ GUEST_DS_AR_BYTES,		"GUEST_DS_AR_BYTES" },
	{ GUEST_FS_AR_BYTES,		"GUEST_FS_AR_BYTES" },
	{ GUEST_GS_AR_BYTES,		"GUEST_GS_AR_BYTES" },
	{ GUEST_LDTR_AR_BYTES,		"GUEST_LDTR_AR_BYTES" },
	{ GUEST_TR_AR_BYTES,		"GUEST_TR_AR_BYTES" },

	{ GUEST_ACTIVITY_STATE,		"GUEST_ACTIVITY_STATE" },
	{ GUEST_SYSENTER_CS,		"GUEST_SYSENTER_CS" },
	{ HOST_SYSENTER_CS,		"HOST_SYSENTER_CS" },

	{ CR0_READ_SHADOW,		"CR0_READ_SHADOW" },
	{ CR4_READ_SHADOW,		"CR4_READ_SHADOW" },

	{ GUEST_CR0,			"GUEST_CR0" },
	{ GUEST_CR3,			"GUEST_CR3" },
	{ GUEST_CR4,			"GUEST_CR4" },

	{ HOST_CR0,			"HOST_CR0" },
	{ HOST_CR3,			"HOST_CR3" },
	{ HOST_CR4,			"HOST_CR4" },

	{ GUEST_ES_BASE, 		"GUEST_ES_BASE" },
	{ GUEST_CS_BASE,		"GUEST_CS_BASE" },
	{ GUEST_SS_BASE,		"GUEST_SS_BASE" },
	{ GUEST_DS_BASE,		"GUEST_DS_BASE" },
	{ GUEST_FS_BASE,		"GUEST_FS_BASE" },
	{ GUEST_GS_BASE,		"GUEST_GS_BASE" },
	{ GUEST_LDTR_BASE,		"GUEST_LDTR_BASE" },
	{ GUEST_TR_BASE,		"GUEST_TR_BASE" },

	{ GUEST_GDTR_BASE,		"GUEST_GDTR_BASE" },
	{ GUEST_IDTR_BASE,		"GUEST_IDTR_BASE" },

	{ GUEST_SYSENTER_ESP,		"GUEST_SYSENTER_ESP" },
	{ GUEST_SYSENTER_EIP,		"GUEST_SYSENTER_EIP" },

	{ GUEST_DR7,			"GUEST_DR7" },
	{ GUEST_RSP,			"GUEST_RSP" },
	{ GUEST_RIP,			"GUEST_RIP" },
	{ GUEST_RFLAGS,			"GUEST_RFLAGS" },

	{ HOST_FS_BASE,			"HOST_FS_BASE" },
	{ HOST_GS_BASE,			"HOST_GS_BASE" },
	{ HOST_TR_BASE,			"HOST_TR_BASE" },

	{ HOST_GDTR_BASE,		"HOST_GDTR_BASE" },
	{ HOST_IDTR_BASE,		"HOST_IDTR_BASE" },

	{ HOST_SYSENTER_ESP,		"HOST_SYSENTER_ESP" },
	{ HOST_SYSENTER_EIP,		"HOST_SYSENTER_EIP" },
	{ HOST_RSP,			"HOST_RSP" },
	{ HOST_RIP,			"HOST_RIP" },

	{ GUEST_INTERRUPTIBILITY_INFO,	"GUEST_INTERRUPTIBILITY_INFO" },
};

const char *get_vmcs_field_str(const enum vmcs_field field)
{
	for (u64 i = 0; i < array_size(vmcs_field_str_array); ++i) {
		if (vmcs_field_str_array[i].field == field)
			return vmcs_field_str_array[i].str;
	}

	return NULL;
}

void dump_x86_regs(struct x86_regs *regs)
{
#define X(x) (regs->x >> 32), (regs->x & 0xffffffff)
	printf("RIP: 0x%x%x\tRSP: 0x%x%x\tRBP: 0x%x%x\tRFLAGS: 0x%x%x\n"
	       "RSI: 0x%x%x\tRDI: 0x%x%x\tRAX: 0x%x%x\tRBX: 0x%x%x\n"
	       "RCX: 0x%x%x\tRDX: 0x%x%x\tR8 : 0x%x%x\tR9 : 0x%x%x\n"
	       "R10: 0x%x%x\tR11: 0x%x%x\tR12: 0x%x%x\tR13: 0x%x%x\n"
	       "R14: 0x%x%x\tR15: 0x%x%x\n", X(rip), X(rsp), X(rbp), X(rflags),
	       X(rsi), X(rdi), X(rax), X(rbx), X(rcx), X(rdx), X(r8), X(r9),
	       X(r10), X(r11), X(r12), X(r13), X(r14), X(r15));
#undef X
}
