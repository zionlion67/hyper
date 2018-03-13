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
	printf("RFLAGS:\t0x%lx\n", state->rflags);
	printf("RSP:\t0x%lx\n", state->rsp);
	printf("RIP:\t0x%lx\n", state->rip);
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
