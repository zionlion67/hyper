#include <stdio.h>
#include <string.h>
#include <page.h>
#include <vmx.h>
#include <io.h>

#include <linux/bootparam.h>
#include <linux/e820.h>

#define VMM_HOST_SEL(vmm, seg) (vmm->host_state.selectors.seg)

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

	//memcpy(vmm->guest_mem_start + (1 << 20), test_code32, SIZEOF_TEST_CODE);

	reg_state->dr7 = read_dr7();
	reg_state->rflags = read_rflags() | 0x2;
	reg_state->rsp = read_rsp();
	reg_state->rip = vmm->guest_mem.start + (1 << 20);
	(void)test_code;

	vmm->guest_state.vmcs_link = (u64)-1ULL;
}

/* Did not type this manually ... */
static void test_code32(void) {
	asm volatile (  "mov	$0x3f8, %edx\n\t"
			"mov    $0x68,%eax\n\t"
			"out    %al,(%dx)\n\t"
			"mov    $0x65,%ebx\n\t"
			"mov    %ebx,%eax\n\t"
			"out    %al,(%dx)\n\t"
			"mov    $0x6c,%eax\n\t"
			"out    %al,(%dx)\n\t"
			"out    %al,(%dx)\n\t"
			"mov    $0x6f,%esi\n\t"
			"mov    %esi,%eax\n\t"
			"out    %al,(%dx)\n\t"
			"mov    $0x20,%ecx\n\t"
			"mov    %ecx,%eax\n\t"
			"out    %al,(%dx)\n\t"
			"mov    $0x66,%eax\n\t"
			"out    %al,(%dx)\n\t"
			"mov    $0x72,%eax\n\t"
			"out    %al,(%dx)\n\t"
			"mov    %esi,%eax\n\t"
			"out    %al,(%dx)\n\t"
			"mov    $0x6d,%eax\n\t"
			"out    %al,(%dx)\n\t"
			"mov    %ecx,%eax\n\t"
			"out    %al,(%dx)\n\t"
			"mov    $0x67,%eax\n\t"
			"out    %al,(%dx)\n\t"
			"mov    $0x75,%eax\n\t"
			"out    %al,(%dx)\n\t"
			"mov    %ebx,%eax\n\t"
			"out    %al,(%dx)\n\t"
			"mov    $0x73,%eax\n\t"
			"out    %al,(%dx)\n\t"
			"mov    $0x74,%eax\n\t"
			"out    %al,(%dx)\n\t"
			"mov    %ecx,%eax\n\t"
			"out    %al,(%dx)\n\t"
			"mov    $0x21,%eax\n\t"
			"out    %al,(%dx)\n\t"
			"mov    $0xd,%eax\n\t"
			"out    %al,(%dx)\n\t"
			"mov    $0xa,%eax\n\t"
			"out    %al,(%dx)\n\t"
			"hlt    \n\t");
}

static void dummy_func(void) {}

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
	seg_desc->db = gdt_desc->db;
	seg_desc->g = gdt_desc->g;
	seg_desc->unusable = 0;

	seg_desc->base_field = base_field;

}

static void setup_x86_control_regs(struct vmm *vmm)
{
	struct vmcs_guest_register_state *state = &vmm->guest_state.reg_state;
	state->control_regs.cr0 = vmm->host_state.control_regs.cr0 & ~CR0_PG;
	state->control_regs.cr4 = vmm->host_state.control_regs.cr4 & ~CR4_PAE;
}

static void setup_x86_tss(struct vmm *vmm)
{
	struct vmcs_guest_register_state *state = &vmm->guest_state.reg_state;
	state->seg_descs.tr.base_field = GUEST_TR_SELECTOR;
	state->seg_descs.tr.selector = 0x18;
	state->seg_descs.tr.type = 0xb /* 32-bit busy TSS */;
	state->seg_descs.tr.s = 0;
	state->seg_descs.tr.p = 1;
	state->seg_descs.tr.g = 0;
	state->seg_descs.tr.limit = 103;
	state->seg_descs.ldtr.base_field = GUEST_LDTR_SELECTOR;
	state->seg_descs.ldtr.unusable = 1;
}

static void setup_x86_seg_descs(struct vmm *vmm)
{
	struct gdt_desc *gdt = get_gdt_ptr();
	struct gdt_desc *cs_desc = gdt + (VMM_HOST_SEL(vmm, cs) >> 3);
	struct gdt_desc *ds_desc = gdt + (VMM_HOST_SEL(vmm, ds) >> 3);

	struct vmcs_guest_register_state *state = &vmm->guest_state.reg_state;

	gate_to_seg_desc(cs_desc, &state->seg_descs.cs,
			 VMM_HOST_SEL(vmm, cs), GUEST_CS_SELECTOR);
	state->seg_descs.cs.type = 0xb;
	state->seg_descs.cs.selector = 0x8;
	state->seg_descs.cs.l = 0;

	gate_to_seg_desc(ds_desc, &state->seg_descs.ds, VMM_HOST_SEL(vmm, ds),
			 GUEST_DS_SELECTOR);
	gate_to_seg_desc(ds_desc, &state->seg_descs.ss, VMM_HOST_SEL(vmm, ss),
			 GUEST_SS_SELECTOR);
	gate_to_seg_desc(ds_desc, &state->seg_descs.es, VMM_HOST_SEL(vmm, es),
			 GUEST_ES_SELECTOR);
	gate_to_seg_desc(ds_desc, &state->seg_descs.fs, VMM_HOST_SEL(vmm, fs),
			 GUEST_FS_SELECTOR);
	gate_to_seg_desc(ds_desc, &state->seg_descs.gs, VMM_HOST_SEL(vmm, gs),
			 GUEST_GS_SELECTOR);
	
	setup_x86_tss(vmm);
}

static void setup_x86_table_regs(struct vmm *vmm)
{
	struct vmcs_guest_register_state *state = &vmm->guest_state.reg_state;

	state->gdtr.base = 0;
	state->idtr.base = 0;
	state->gdtr.limit = 0xffff;
	state->idtr.limit = 0xffff;
}

static void setup_x86_default_regs(struct vmm *vmm)
{
	setup_x86_control_regs(vmm);
	setup_x86_seg_descs(vmm);
	setup_x86_table_regs(vmm);

	vmm->guest_state.reg_state.dr7 = 0x400;
	vmm->guest_state.reg_state.rflags = 0x2;
}

#define VMX_NO_VMCS_LINK ~((u64)0ULL)
int setup_test_guest32(struct vmm *vmm)
{
	setup_x86_default_regs(vmm);
	vmm->guest_state.vmcs_link = VMX_NO_VMCS_LINK;

	/* +4 is hack to skip 64 bit prologue */
	memcpy(vmm->guest_mem.start + (1 << 20), test_code32 + 4,
	       (u64)dummy_func - (u64)test_code32);

	vmm->guest_state.reg_state.rsp = 0x400000;
	vmm->guest_state.reg_state.rip = (1 << 20);

	return 0;
}

#define SETUP_HDR_OFFSET	0x1f1
#define SECTOR_SIZE		512

#define BOOTLOADER_UNDEFINED	0xff
#define BOOT_SECTOR_ADDR	0x6000
#define COMMAND_LINE_ADDR	(BOOT_SECTOR_ADDR + 0x10000)
#define LINUX_KERNEL_LOAD_ADDR	0x100000

static inline void set_e820_entry(struct boot_e820_entry *entry, u64 addr,
				  u64 size, u32 type)
{
	entry->addr = addr;
	entry->size = size;
	entry->type = type;
}

static void init_e820_table(struct boot_params *params)
{
	u8 idx = 0;
	struct boot_e820_entry *pre_isa = &params->e820_table[idx++];
	struct boot_e820_entry *post_isa = &params->e820_table[idx++];

	set_e820_entry(pre_isa, 0x0, ISA_START_ADDRESS - 1, E820_RAM);
	set_e820_entry(post_isa, ISA_END_ADDRESS, 0xffffffff - ISA_END_ADDRESS,
		       E820_RAM);

	params->e820_entries = idx;
}

static void init_linux_boot_params(struct boot_params *params)
{
	if (params->hdr.setup_sects == 0)
		params->hdr.setup_sects = 4;

	params->hdr.type_of_loader = BOOTLOADER_UNDEFINED;

	u8 loadflags = params->hdr.loadflags;
	loadflags |= KEEP_SEGMENTS; /* Do not reload segments */
	loadflags &= ~QUIET_FLAG; /* Print early messages */
	loadflags &= ~CAN_USE_HEAP; /* heap_ptr is not valid */
	params->hdr.loadflags = loadflags;

	params->hdr.cmd_line_ptr = COMMAND_LINE_ADDR;

	init_e820_table(params);
}

static char *read_kernel_version(struct vmm *vmm, struct setup_header *hdr)
{
	char *kversion = "failed to retrieve kernel version";
	u8 sect = (hdr->kernel_version >> 9) + 1;

	char *img_start = (char *)vmm->guest_img.start;
	if (hdr->setup_sects >= sect)
		 kversion = img_start + hdr->kernel_version + SECTOR_SIZE;
	return kversion;
}

static void setup_linux_cmdline(struct vmm *vmm, const char *cmdline)
{
	u64 cmdline_len = strlen(cmdline);
	void *cmdline_ptr = (void *)(vmm->guest_mem.start + COMMAND_LINE_ADDR);
	memset(cmdline_ptr, 0, cmdline_len + 1);
	memcpy(cmdline_ptr, cmdline, cmdline_len);
}

static inline void map_linux_kernel(vaddr_t ram_start, vaddr_t img_start,
				    vaddr_t img_end, u64 kernel_offset)
{
	void *kernel = (void *)(img_start + kernel_offset);
	u64 kernel_sz = (img_end - img_start) - kernel_offset;
	
	memcpy((void *)(ram_start + LINUX_KERNEL_LOAD_ADDR), kernel, kernel_sz);
}

int setup_linux_guest(struct vmm *vmm)
{
	setup_x86_default_regs(vmm);

	vaddr_t ram_start = vmm->guest_mem.start;
	vaddr_t img_start = vmm->guest_img.start;
	vaddr_t img_end   = vmm->guest_img.end;

	struct setup_header *hdr = (void *)(img_start + SETUP_HDR_OFFSET);

	printf("Linux Version: %s\n", read_kernel_version(vmm, hdr));

	struct boot_params *boot_params = (void *)(ram_start + BOOT_SECTOR_ADDR);
	memset(boot_params, 0, sizeof(struct boot_params));
	
	/* from Documentation/x86/boot.txt:
	 * The end of setup header can be calculated as follow:
	 * 	0x0202 + byte value at offset 0x0201
	 */
	u64 setup_hdr_end = 0x202 + ((u8 *)img_start)[0x201];
	memcpy(&boot_params->hdr, hdr, setup_hdr_end - SETUP_HDR_OFFSET);
	init_linux_boot_params(boot_params);

	/* TODO remove hardcoded cmdline */
	const char *cmdline = "console=ttyS0 earlyprintk=serial";
	setup_linux_cmdline(vmm, cmdline);

	u64 kernel_offset = (boot_params->hdr.setup_sects + 1) * SECTOR_SIZE;
	map_linux_kernel(ram_start, img_start, img_end, kernel_offset);

	/* TODO add initrd */

	struct vmcs_guest_register_state *state = &vmm->guest_state.reg_state;
	state->rsp = 0x400000;
	state->rip = LINUX_KERNEL_LOAD_ADDR;
	state->rsi = BOOT_SECTOR_ADDR;
	state->rdi = 0;
	state->rbp = 0;
	state->rbx = 0;

	vmm->guest_state.vmcs_link = VMX_NO_VMCS_LINK;
	return 0;
}
