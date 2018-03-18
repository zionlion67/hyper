#include <stdio.h>
#include <string.h>
#include <page.h>
#include <vmx.h>
#include <io.h>

static void gate_to_seg_desc(struct gdt_desc *gdt_desc,
		             struct segment_descriptor *seg_desc, u16 sel,
			     enum vmcs_field base_field)
{
	seg_desc->selector = sel;
	seg_desc->base = ((u64)gdt_desc->base_lo|((u64)gdt_desc->base_mi << 16)
			 |((u64)gdt_desc->base_hi << 24));

	seg_desc->limit = ~(u32)0;

	seg_desc->access = 0;
	seg_desc->type = gdt_desc->type;
	seg_desc->s = 1;
	seg_desc->dpl = gdt_desc->dpl;
	seg_desc->p = gdt_desc->p;
	seg_desc->avl = gdt_desc->avl;
	seg_desc->l = 0;
	seg_desc->db = 1;//gdt_desc->db;
	seg_desc->g = gdt_desc->g;
	seg_desc->unusable = 0;

	seg_desc->base_field = base_field;

}

#define SIZEOF_TEST_CODE 117
static const char *test_code32 =
"\x56\xba\xf8\x03\x00\x00\x53\xb8\x68\x00\x00"
"\x00\xee\xbb\x65\x00\x00\x00\x89\xd8\xee\xb8"
"\x6c\x00\x00\x00\xee\xee\xbe\x6f\x00\x00\x00"
"\x89\xf0\xee\xb9\x20\x00\x00\x00\x89\xc8\xee"
"\xb8\x66\x00\x00\x00\xee\xb8\x72\x00\x00\x00"
"\xee\x89\xf0\xee\xb8\x6d\x00\x00\x00\xee\x89"
"\xc8\xee\xb8\x67\x00\x00\x00\xee\xb8\x75\x00"
"\x00\x00\xee\x89\xd8\xee\xb8\x73\x00\x00\x00"
"\xee\xb8\x74\x00\x00\x00\xee\x89\xc8\xee\xb8"
"\x21\x00\x00\x00\xee\xb8\x0d\x00\x00\x00\xee"
"\xb8\x0a\x00\x00\x00\xee\xf4";

#define VMM_HOST_SEL(vmm, seg) (vmm->host_state.selectors.seg)
void setup_test_guest32(struct vmm *vmm)
{
	struct vmcs_guest_register_state *reg_state = &vmm->guest_state.reg_state;
	reg_state->control_regs.cr0 = vmm->host_state.control_regs.cr0 & ~CR0_PG;
	reg_state->control_regs.cr4 = vmm->host_state.control_regs.cr4;

	struct gdt_desc *gdt = get_gdt_ptr();
	struct gdt_desc *cs_desc = gdt + (VMM_HOST_SEL(vmm, cs) >> 3);
	struct gdt_desc *ds_desc = gdt + (VMM_HOST_SEL(vmm, ds) >> 3);


	gate_to_seg_desc(cs_desc, &reg_state->seg_descs.cs,
			 VMM_HOST_SEL(vmm, cs), GUEST_CS_SELECTOR);
	reg_state->seg_descs.cs.type = 0xb;
	reg_state->seg_descs.cs.selector = 0x8;
	reg_state->seg_descs.cs.l = 0;
	gate_to_seg_desc(ds_desc, &reg_state->seg_descs.ds,
			 VMM_HOST_SEL(vmm, ds), GUEST_DS_SELECTOR);
	gate_to_seg_desc(ds_desc, &reg_state->seg_descs.ss,
			 VMM_HOST_SEL(vmm, ss), GUEST_SS_SELECTOR);
	gate_to_seg_desc(ds_desc, &reg_state->seg_descs.es,
			 VMM_HOST_SEL(vmm, es), GUEST_ES_SELECTOR);
	gate_to_seg_desc(ds_desc, &reg_state->seg_descs.fs,
			 VMM_HOST_SEL(vmm, fs), GUEST_FS_SELECTOR);
	gate_to_seg_desc(ds_desc, &reg_state->seg_descs.gs,
			 VMM_HOST_SEL(vmm, gs), GUEST_GS_SELECTOR);

	reg_state->seg_descs.tr.base_field = GUEST_TR_SELECTOR;
	reg_state->seg_descs.tr.selector = 0x18;
	reg_state->seg_descs.tr.type = 0xb /* 32-bit busy TSS */;
	reg_state->seg_descs.tr.s = 0;
	reg_state->seg_descs.tr.p = 1;
	reg_state->seg_descs.tr.g = 0;
	reg_state->seg_descs.tr.limit = 103;
	reg_state->seg_descs.ldtr.base_field = GUEST_LDTR_SELECTOR;
	reg_state->seg_descs.ldtr.unusable = 1;


	reg_state->gdtr.base = 0;
	reg_state->idtr.base = 0;
	reg_state->gdtr.limit = 0xffff;
	reg_state->idtr.limit = 0xffff;

	vmm->guest_state.vmcs_link = (u64)-1ULL;

	memcpy(vmm->guest_mem_start + (1 << 20), test_code32, SIZEOF_TEST_CODE);

	reg_state->dr7 = 0x400;
	reg_state->rflags = 0x2;
	reg_state->rsp = 0x400000;
	reg_state->rip = (1 << 20);
}

static void gate_to_seg_desc64(struct gdt_desc *gdt_desc,
		               struct segment_descriptor *seg_desc, u16 sel,
			       enum vmcs_field base_field)
{
	seg_desc->selector = sel;
	seg_desc->base = ((u64)gdt_desc->base_lo|((u64)gdt_desc->base_mi << 16)
			 |((u64)gdt_desc->base_hi << 24));

	seg_desc->limit = (u32)~0;

	seg_desc->access = 0;
	seg_desc->type = gdt_desc->type;
	seg_desc->s = 1;
	seg_desc->dpl = gdt_desc->dpl;
	seg_desc->p = gdt_desc->p;
	seg_desc->avl = gdt_desc->avl;
	seg_desc->l = gdt_desc->l;
	seg_desc->db = gdt_desc->db;
	seg_desc->g = gdt_desc->g;
	seg_desc->unusable = 0;

	seg_desc->base_field = base_field;

}

static void test_code(void)
{
#define X(c) outb(0x3f8, (c))
	X('h');
	X('e');
	X('l');
	X('l');
	X('o');
	X(' ');
	X('f');
	X('r');
	X('o');
	X('m');
	X(' ');
	X('g');
	X('u');
	X('e');
	X('s');
	X('t');
	X('\r');
	X('\n');
#undef X
}

void setup_test_guest(struct vmm *vmm)
{
	struct vmcs_guest_register_state *reg_state = &vmm->guest_state.reg_state;
	reg_state->control_regs.cr0 = vmm->host_state.control_regs.cr0;
	reg_state->control_regs.cr3 = vmm->host_state.control_regs.cr3;
	reg_state->control_regs.cr4 = vmm->host_state.control_regs.cr4;

	struct gdt_desc *gdt = get_gdt_ptr();
	struct gdt_desc *cs_desc = gdt + (VMM_HOST_SEL(vmm, cs) >> 3);
	struct gdt_desc *ds_desc = gdt + (VMM_HOST_SEL(vmm, ds) >> 3);
	struct gdt_desc *tr_desc = gdt + (VMM_HOST_SEL(vmm, tr) >> 3);

	cs_desc->type = 0xb;

	gate_to_seg_desc64(cs_desc, &reg_state->seg_descs.cs,
			   VMM_HOST_SEL(vmm, cs), GUEST_CS_SELECTOR);
	gate_to_seg_desc64(ds_desc, &reg_state->seg_descs.ds,
			   VMM_HOST_SEL(vmm, ds), GUEST_DS_SELECTOR);
	gate_to_seg_desc64(ds_desc, &reg_state->seg_descs.es,
			   VMM_HOST_SEL(vmm, es), GUEST_ES_SELECTOR);
	gate_to_seg_desc64(ds_desc, &reg_state->seg_descs.ss,
			   VMM_HOST_SEL(vmm, ss), GUEST_SS_SELECTOR);
	gate_to_seg_desc64(ds_desc, &reg_state->seg_descs.fs,
			   VMM_HOST_SEL(vmm, fs), GUEST_FS_SELECTOR);
	gate_to_seg_desc64(ds_desc, &reg_state->seg_descs.gs,
			   VMM_HOST_SEL(vmm, gs), GUEST_GS_SELECTOR);
	gate_to_seg_desc64(tr_desc, &reg_state->seg_descs.tr,
			   VMM_HOST_SEL(vmm, tr), GUEST_TR_SELECTOR);

	reg_state->seg_descs.tr.base = 0;
	reg_state->seg_descs.tr.limit = 103;
	reg_state->seg_descs.tr.g = 0;
	reg_state->seg_descs.tr.s = 0;
	reg_state->seg_descs.ldtr.base_field = GUEST_LDTR_SELECTOR;
	reg_state->seg_descs.ldtr.unusable = 1;

	struct gdtr host_gdtr;
	__sgdt(&host_gdtr);
	reg_state->gdtr.base = host_gdtr.base;
	reg_state->gdtr.limit = host_gdtr.limit;

	__sidt(&host_gdtr);
	reg_state->idtr.base = host_gdtr.base;
	reg_state->idtr.limit = host_gdtr.limit;

	memcpy(&reg_state->msr, &vmm->host_state.msr, sizeof(struct vmcs_state_msr));

	memcpy(vmm->guest_mem_start + (1 << 20), test_code32, SIZEOF_TEST_CODE);

	reg_state->dr7 = read_dr7();
	reg_state->rflags = read_rflags() | 0x2;
	reg_state->rsp = read_rsp();
	reg_state->rip = vmm->guest_mem_start + (1 << 20);
	(void)test_code;

	vmm->guest_state.vmcs_link = (u64)-1ULL;
}