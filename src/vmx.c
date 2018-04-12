#include <cpuid.h>	/* compiler header */

#include <compiler.h>
#include <gdt.h>
#include <kmalloc.h>
#include <page.h>
#include <memory.h>
#include <string.h>
#include <stdio.h>

#include <vmx.h>

#ifndef __clang__
#define bit_VMX	0x20
#endif

/* TSS definition is not exported */
extern char tss[];

struct vmcs {
	u32	rev_id;
	u32	vmx_abort;
	u8	data[0];
} __packed;

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

static inline void vmm_read_vmx_msrs(struct vmm *vmm)
{
	for (u64 i = 0; i < NR_VMX_MSR; ++i)
		vmm->vmx_msr[i] = __readmsr(MSR_VMX_BASIC + i);
}

static int alloc_vmcs(struct vmm *vmm)
{
	/*
	 * Ugly hack to avoid wasting too much memory without modifying
	 * the 2mb page allocator.
	 */
	void *mem = alloc_page();
	if (mem == NULL)
		return 1;
	memset(mem, 0, ALLOC_PAGE_SIZE);
	vmm->vmx_on = mem;
	vmm->vmcs = (vaddr_t)mem + PAGE_SIZE;
	return 0;
}

static inline void release_vmcs(struct vmcs *vmcs)
{
	release_page(vmcs);
}

/* Write back caching */
#define EPT_MEMORY_TYPE_WB	0x6

static void setup_eptp(struct eptp *eptp, struct ept_pml4e *ept_pml4)
{
	eptp->quad_word = 0;
	eptp->type = EPT_MEMORY_TYPE_WB;
	eptp->page_walk_length = 3;
	eptp->enable_dirty_flag = 0;
	eptp->pml4_addr = virt_to_phys(ept_pml4) >> PAGE_SHIFT;
}

static inline void ept_set_pte_rwe(void *ept_pte)
{
	struct ept_pte *pte = (struct ept_pte *)ept_pte;
	pte->read = 1;
	pte->write = 1;
	pte->kern_exec = 1;
}

#define _1GB (1024 * 1024 * 1024)
#define _2MB (2 << 20)


//TODO add nb page
static void ept_init_pt(struct ept_pte *ept_pte, paddr_t host_addr,
			 paddr_t guest_addr)
{
	u16 pte_off = pte_offset(guest_addr);
	for (u16 i = 0; pte_off < EPT_PTRS_PER_TABLE; ++pte_off, ++i) {
		struct ept_pte *pte = ept_pte + pte_off;
		ept_set_pte_rwe(pte);
		pte->memory_type = EPT_MEMORY_TYPE_WB;
		pte->ignore_pat = 1;
		pte->paddr = (host_addr + i * PAGE_SIZE) >> PAGE_SHIFT;
	}
}

static int ept_alloc_set_pgtables(struct ept_pde *ept_pde, paddr_t host_addr,
				  paddr_t guest_addr, u16 nb_entries)
{
	vaddr_t pgtable_vaddr = (vaddr_t)alloc_page();
	if ((void *)pgtable_vaddr == NULL)
		return 1;

	u16 pmd_off = pmd_offset(guest_addr);
	for (u16 i = 0; i < nb_entries && pmd_off + i < EPT_PTRS_PER_TABLE; ++i) {
		struct ept_pde *cur_pde = ept_pde + pmd_off + i;
		ept_set_pte_rwe(cur_pde);
		struct ept_pte *pt = (void *)(pgtable_vaddr + i * PAGE_SIZE);
		ept_init_pt(pt, host_addr + i * _2MB, guest_addr);
		cur_pde->paddr = virt_to_phys(pt) >> PAGE_SHIFT;
	}

	return 0;
}

/*
 * Build EPT structures. Only RWE mappings atm.
 * XXX: atm, KVM only support nested EPT translations using 4 level structures
 * (not more not less), so we'll stick to that. 512G max supported here.
 */
static int ept_setup_range(struct vmm *vmm, paddr_t host_start,
			    paddr_t host_end, paddr_t guest_start)
{
	/*
	 * vmx_on and vmcs are stored on a 2MB page ...
	 * There is 2MB - 8KB of space left for EPT structures.
	 */
	struct ept_pml4e *ept_pml4 = (vaddr_t)vmm->vmx_on + 2 * PAGE_SIZE;
	struct ept_pdpte *ept_pdpt = (vaddr_t)ept_pml4 + PAGE_SIZE;
	struct ept_pde *ept_pde = (vaddr_t)ept_pdpt + PAGE_SIZE;

	struct ept_pml4e *pml4e = ept_pml4 + pgd_offset(guest_start);
	ept_set_pte_rwe(pml4e);
	pml4e->paddr = virt_to_phys(ept_pdpt) >> PAGE_SHIFT;

	struct ept_pdpte *pdpte = ept_pdpt + pud_offset(guest_start);
	ept_set_pte_rwe(pdpte);

	/* compute how much EPT PD we can store without allocating a new page */
	u64 max_pd = (ALLOC_PAGE_SIZE - ((vaddr_t)ept_pde - (vaddr_t)vmm->vmx_on))
		      / PAGE_SIZE;

	/* one page directory maps 1GB of RAM */
	u64 needed_pd = (host_end - host_start) / _1GB;
	if (!needed_pd)
		needed_pd = 1;
	if (needed_pd > max_pd)
		return 1;

	/* one page table maps 2MB of RAM */
	u16 needed_pgtable = (host_end - host_start) / _2MB;
	for (u64 i = 0; i < needed_pd; ++i, ++pdpte) {
		struct ept_pde *cur_pde = (vaddr_t)ept_pde + i * PAGE_SIZE;
		ept_set_pte_rwe(cur_pde);
		pdpte->paddr = virt_to_phys(cur_pde) >> PAGE_SHIFT;

		u16 nb_pgtable = EPT_PTRS_PER_TABLE;
		if (i == needed_pd - 1)
			nb_pgtable = needed_pgtable - i * EPT_PTRS_PER_TABLE;

		if (ept_alloc_set_pgtables(cur_pde, host_start, guest_start,
					   nb_pgtable)) {
			return 1;
		}

		host_start += nb_pgtable * _2MB;
		guest_start += nb_pgtable * _2MB;
	}

	setup_eptp(&vmm->eptp, ept_pml4);

	return 0;
}


/* XXX: ATM allocates 200M of memory for the VM */
static int setup_ept(struct vmm *vmm)
{
	u8 nb_pages = 100;
	void *p = alloc_pages(nb_pages);
	if (p == NULL)
		return 1;

	paddr_t start = virt_to_phys(p);
	paddr_t end = start + nb_pages * ALLOC_PAGE_SIZE;
	if (ept_setup_range(vmm, start, end, 0))
		return 1;
	vmm->guest_mem.start = p;
	vmm->guest_mem.end = phys_to_virt(end);
	return 0;
}

paddr_t ept_translate(struct eptp *eptp, paddr_t addr)
{
	paddr_t pgd_addr = eptp->pml4_addr << PAGE_SHIFT;
	struct ept_pml4e *pgd = (void *)phys_to_virt(pgd_addr);
	u16 pgd_off = pgd_offset(addr);
	if (!pg_present(pgd[pgd_off].quad_word))
		return (paddr_t)-1;

	paddr_t pud_addr = (paddr_t)(pgd[pgd_off].quad_word & PAGE_MASK);
	struct ept_pdpte *pud = (void *)phys_to_virt(pud_addr);
	u16 pud_off = pud_offset(addr);
	if (!pg_present(pud[pud_off].quad_word))
		return (paddr_t)-1;

	paddr_t pmd_addr = (paddr_t)(pud[pud_off].quad_word & PAGE_MASK);
	struct ept_pde *pmd = (void *)phys_to_virt(pmd_addr);
	u16 pmd_off = pmd_offset(addr);
	if (!pg_present(pmd[pmd_off].quad_word))
		return (paddr_t)-1;

	paddr_t pt_addr = (paddr_t)(pmd[pmd_off].quad_word & PAGE_MASK);
	struct ept_pte *pte = (void *)phys_to_virt(pt_addr);
	u16 pte_off = pte_offset(addr);
	if (!pg_present(pte[pte_off].quad_word))
		return (paddr_t)-1;

	u16 page_off = addr & ~PAGE_MASK;
	return (paddr_t)((pte[pte_off].quad_word & PAGE_MASK) + page_off);
}

static void vmcs_get_host_selectors(struct segment_selectors *sel)
{
	sel->cs = read_cs();
	sel->ds = read_ds();
	sel->es = read_es();
	sel->ss = read_ss();
	sel->fs = read_fs();
	sel->gs = read_gs();
	sel->tr = __str();
}

static void vmcs_get_control_regs(struct control_regs *regs)
{
	regs->cr0 = read_cr0();
	regs->cr3 = read_cr3();
	regs->cr4 = read_cr4();
}

static void vmcs_fill_msr_state(struct vmcs_state_msr *msr)
{
	msr->ia32_fs_base = __readmsr(MSR_FS_BASE);
	msr->ia32_gs_base = __readmsr(MSR_GS_BASE);
	msr->ia32_sysenter_cs = __readmsr(MSR_SYSENTER_CS);
	msr->ia32_sysenter_esp = __readmsr(MSR_SYSENTER_ESP);
	msr->ia32_sysenter_eip = __readmsr(MSR_SYSENTER_EIP);
	msr->ia32_perf_global_ctrl = __readmsr(MSR_PERF_GLOBAL_CTRL);
	msr->ia32_pat = __readmsr(MSR_PAT);
	msr->ia32_efer = __readmsr(MSR_EFER);
	msr->ia32_debugctl = __readmsr(MSR_DEBUGCTL);
#if 0
	msr->ia32_bndcfgs = __readmsr(MSR_BNDCFGS);
#endif
}

#define VM_EXIT_STACK_SIZE	(PAGE_SIZE - 32)
extern void vm_exit_stub(void);
static int vmcs_get_host_state(struct vmcs_host_state *state)
{
	vmcs_get_control_regs(&state->control_regs);
	vmcs_get_host_selectors(&state->selectors);

	struct gdtr gdtr;
	__sgdt(&gdtr);
	state->gdtr_base = gdtr.base;

	__sidt(&gdtr); /* gdtr has the same memory layout */
	state->idtr_base = gdtr.base;
	state->tr_base = (u64)tss;

	vmcs_fill_msr_state(&state->msr);

	void *ptr = kmalloc(PAGE_SIZE);
	if (ptr == NULL)
		return 1;
	state->rsp = (u64)ptr + VM_EXIT_STACK_SIZE;
	state->rip = (u64)vm_exit_stub;
	return 0;
}

static inline void host_set_stack_ctx(struct vmm *vmm)
{
	*((void **)vmm->host_state.rsp) = (void *)vmm;
}

#define VMM_IDX(idx) 		((idx) - MSR_VMX_BASIC)
#define VMM_MSR_VMX_BASIC	VMM_IDX(MSR_VMX_BASIC)
#define VMM_MSR_VMX_CR0_FIXED0	VMM_IDX(MSR_VMX_CR0_FIXED0)
#define VMM_MSR_VMX_CR0_FIXED1	VMM_IDX(MSR_VMX_CR0_FIXED1)
#define VMM_MSR_VMX_CR4_FIXED0	VMM_IDX(MSR_VMX_CR4_FIXED0)
#define VMM_MSR_VMX_CR4_FIXED1	VMM_IDX(MSR_VMX_CR4_FIXED1)

static inline void vmcs_write_control(struct vmm *vmm, enum vmcs_field field,
				      u64 ctl, u64 ctl_msr)
{
	u64 ctl_mask = vmm->vmx_msr[VMM_IDX(ctl_msr)];
	__vmwrite(field, adjust_vm_control(ctl, ctl_mask));
}

static inline void vmcs_write_pin_based_ctrls(struct vmm *vmm, u64 ctl)
{
	vmcs_write_control(vmm, PIN_BASED_VM_EXEC_CONTROL, ctl,
			   MSR_VMX_TRUE_PIN_CTLS);
}

static inline void vmcs_write_proc_based_ctrls(struct vmm *vmm, u64 ctl)
{
	vmcs_write_control(vmm, CPU_BASED_VM_EXEC_CONTROL, ctl,
			   MSR_VMX_TRUE_PROC_CTLS);
}

static inline void vmcs_write_proc_based_ctrls2(struct vmm *vmm, u64 ctl)
{

	vmcs_write_control(vmm, SECONDARY_VM_EXEC_CONTROL, ctl,
			   MSR_VMX_PROC_CTLS2);
}

/* TODO add MSR Bitmap */
static void vmcs_write_vm_exec_controls(struct vmm *vmm)
{
	vmcs_write_pin_based_ctrls(vmm, 0);

	u64 proc_flags1 = VM_EXEC_USE_MSR_BITMAPS|VM_EXEC_ENABLE_PROC_CTLS2;
	u64 proc_flags2 = VM_EXEC_UNRESTRICTED_GUEST|VM_EXEC_ENABLE_EPT;
	vmcs_write_proc_based_ctrls(vmm, proc_flags1);
	vmcs_write_proc_based_ctrls2(vmm, proc_flags2);

	__vmwrite(EXCEPTION_BITMAP, 0);

	paddr_t addr = virt_to_phys(__align_n((u64)vmm->msr_bitmap, PAGE_SIZE));
	__vmwrite(MSR_BITMAP, addr);

	__vmwrite(CR0_READ_SHADOW, vmm->host_state.control_regs.cr0);
	__vmwrite(CR4_READ_SHADOW, vmm->host_state.control_regs.cr4);
	__vmwrite(EPT_POINTER, vmm->eptp.quad_word);
}

static void vmcs_write_vm_exit_controls(struct vmm *vmm)
{
	vmcs_write_control(vmm, VM_EXIT_CONTROLS, VM_EXIT_LONG_MODE,
			   MSR_VMX_TRUE_EXIT_CTLS);
}

/* TODO check if guest is in LM or PM */
static void vmcs_write_vm_entry_controls(struct vmm *vmm)
{
	vmcs_write_control(vmm, VM_ENTRY_CONTROLS, 0,
			   MSR_VMX_TRUE_ENTRY_CTLS);
}

static void vmcs_write_control_regs(struct control_regs *regs, int host)
{
	enum vmcs_field base_field;
	if (host)
		base_field = HOST_CR0;
	else
		base_field = GUEST_CR0;

	__vmwrite(base_field, regs->cr0);
	__vmwrite(base_field + 2, regs->cr3);
	__vmwrite(base_field + 4, regs->cr4);
}

static void vmcs_write_vm_host_state(struct vmm *vmm)
{
	vmcs_write_control_regs(&vmm->host_state.control_regs, 1);

	__vmwrite(HOST_CS_SELECTOR, vmm->host_state.selectors.cs);
	__vmwrite(HOST_DS_SELECTOR, vmm->host_state.selectors.ds);
	__vmwrite(HOST_ES_SELECTOR, vmm->host_state.selectors.es);
	__vmwrite(HOST_SS_SELECTOR, vmm->host_state.selectors.ss);
	__vmwrite(HOST_FS_SELECTOR, vmm->host_state.selectors.fs);
	__vmwrite(HOST_GS_SELECTOR, vmm->host_state.selectors.gs);
	__vmwrite(HOST_TR_SELECTOR, vmm->host_state.selectors.tr);

	__vmwrite(HOST_TR_BASE, vmm->host_state.tr_base);
	__vmwrite(HOST_GDTR_BASE, vmm->host_state.gdtr_base);
	__vmwrite(HOST_IDTR_BASE, vmm->host_state.idtr_base);
	__vmwrite(HOST_FS_BASE, vmm->host_state.msr.ia32_fs_base);
	__vmwrite(HOST_GS_BASE, vmm->host_state.msr.ia32_gs_base);

	__vmwrite(HOST_SYSENTER_CS, vmm->host_state.msr.ia32_sysenter_cs);
	__vmwrite(HOST_SYSENTER_ESP, vmm->host_state.msr.ia32_sysenter_esp);
	__vmwrite(HOST_SYSENTER_EIP, vmm->host_state.msr.ia32_sysenter_eip);

	__vmwrite(HOST_PERF_GLOBAL_CTRL, vmm->host_state.msr.ia32_perf_global_ctrl);
	__vmwrite(HOST_PAT, vmm->host_state.msr.ia32_pat);
	__vmwrite(HOST_EFER, vmm->host_state.msr.ia32_efer);

	__vmwrite(HOST_RSP, vmm->host_state.rsp);
	__vmwrite(HOST_RIP, vmm->host_state.rip);
}

static inline enum vmcs_field sel_offset(enum vmcs_field field)
{
	return field - GUEST_ES_SELECTOR;
}

static inline enum vmcs_field sel_limit(enum vmcs_field field)
{
	return sel_offset(GUEST_ES_LIMIT) + field;
}

static inline enum vmcs_field sel_access(enum vmcs_field field)
{
	return sel_offset(GUEST_ES_AR_BYTES) + field;
}

static inline enum vmcs_field sel_base(enum vmcs_field field)
{
	return sel_offset(GUEST_ES_BASE) + field;
}

static void vmcs_write_guest_selector(struct segment_descriptor *desc)
{
	enum vmcs_field field = desc->base_field;
	__vmwrite(field, desc->selector);
	__vmwrite(sel_limit(field), desc->limit);
	__vmwrite(sel_access(field), desc->access);
	__vmwrite(sel_base(field), desc->base);
}

static void vmcs_write_guest_selectors(struct segment_descriptors *desc)
{
	vmcs_write_guest_selector(&desc->cs);
	vmcs_write_guest_selector(&desc->ds);
	vmcs_write_guest_selector(&desc->es);
	vmcs_write_guest_selector(&desc->ss);
	vmcs_write_guest_selector(&desc->fs);
	vmcs_write_guest_selector(&desc->gs);
	vmcs_write_guest_selector(&desc->tr);
	vmcs_write_guest_selector(&desc->ldtr);
}

static void vmcs_write_guest_reg_state(struct vmcs_guest_register_state *state)
{
	vmcs_write_control_regs(&state->control_regs, 0);
	vmcs_write_guest_selectors(&state->seg_descs);

	__vmwrite(GUEST_GDTR_BASE, state->gdtr.base);
	__vmwrite(GUEST_IDTR_BASE, state->idtr.base);
	__vmwrite(GUEST_GDTR_LIMIT, state->gdtr.limit);
	__vmwrite(GUEST_IDTR_LIMIT, state->idtr.limit);

	__vmwrite(GUEST_SYSENTER_CS, state->msr.ia32_sysenter_cs);
	__vmwrite(GUEST_SYSENTER_ESP, state->msr.ia32_sysenter_esp);
	__vmwrite(GUEST_SYSENTER_EIP, state->msr.ia32_sysenter_eip);

	__vmwrite(GUEST_PAT, state->msr.ia32_pat);
	__vmwrite(GUEST_EFER, state->msr.ia32_efer);
	__vmwrite(GUEST_BNDCFGS, state->msr.ia32_bndcfgs);
	__vmwrite(GUEST_DEBUGCTL, state->msr.ia32_debugctl);
	__vmwrite(GUEST_PERF_GLOBAL_CTRL, state->msr.ia32_perf_global_ctrl);
	__vmwrite(GUEST_DR7, state->dr7);

	__vmwrite(GUEST_RFLAGS, state->regs.rflags);
	__vmwrite(GUEST_RSP, state->regs.rsp);
	__vmwrite(GUEST_RIP, state->regs.rip);

	__vmwrite(GUEST_ACTIVITY_STATE, 0);
	__vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
}

static void vmcs_write_guest_state(struct vmcs_guest_state *state)
{
	vmcs_write_guest_reg_state(&state->reg_state);

	__vmwrite(VMCS_LINK_POINTER, state->vmcs_link);
}

static inline void vmcs_write_vm_guest_state(struct vmm *vmm)
{
	vmcs_write_guest_state(&vmm->guest_state);
}

#define MSR_BITMAP_SZ		1024
#define MSR_ALL_BITMAP_SZ	(4 * MSR_BITMAP_SZ)
#define MSR_BITMAP_READ_LO	0
#define MSR_BITMAP_READ_HI	(MSR_BITMAP_READ_LO + MSR_BITMAP_SZ)
#define MSR_BITMAP_WRITE_LO	(MSR_BITMAP_READ_HI + MSR_BITMAP_SZ)
#define MSR_BITMAP_WRITE_HI	(MSR_BITMAP_WRITE_LO + MSR_BITMAP_SZ)

/* Yet another ugly hack ... */
static int init_msr_bitmap(struct vmm *vmm)
{
	vmm->msr_bitmap = kmalloc(MSR_ALL_BITMAP_SZ * 2);
	if (vmm->msr_bitmap == NULL)
		return 1;

	memset(vmm->msr_bitmap, 0, MSR_ALL_BITMAP_SZ * 2);
	return 0;
}

/* Hack to launch linux with correct reg state, this is really ugly. */
static int launch_vm(struct vmm *vmm)
{
	struct vmcs_guest_register_state *state = &vmm->guest_state.reg_state;
	asm volatile goto ("movq %3, %%rbp\n\t"
			   "vmlaunch\n\t"
			   "jbe %l4"
			   : /* No output */
			   : "S"(state->regs.rsi), "D"(state->regs.rdi),
			     "r"(state->regs.rbp), "b"(state->regs.rbx)
			   : "memory"
			   : fail
			  );
	return 0;
fail:
	return 1;
}

int vmm_init(struct vmm *vmm)
{
	vmm_read_vmx_msrs(vmm);
	if (alloc_vmcs(vmm))
		return 1;

	u32 rev_id = vmm->vmx_msr[VMM_MSR_VMX_BASIC] & 0x7fffffff;
	vmm->vmcs->rev_id = rev_id;
	vmm->vmx_on->rev_id = rev_id;

	u64 cr0 = read_cr0();
	cr0 |= vmm->vmx_msr[VMM_MSR_VMX_CR0_FIXED0];
	cr0 &= vmm->vmx_msr[VMM_MSR_VMX_CR0_FIXED1];
	write_cr0(cr0);

	u64 cr4 = read_cr4();
	cr4 |= CR4_VMXE;
	cr4 |= vmm->vmx_msr[VMM_MSR_VMX_CR4_FIXED0];
	cr4 &= vmm->vmx_msr[VMM_MSR_VMX_CR4_FIXED1];
	write_cr4(cr4);

	if (vmcs_get_host_state(&vmm->host_state)) {
		printf("Failed to setup host state\n");
		goto free_vmcs;
	}

	host_set_stack_ctx(vmm);

	if (setup_ept(vmm)) {
		printf("Failed to setup EPT\n");
		goto free_host;
	}

	if (init_msr_bitmap(vmm))
		goto free_host;

	vmm->setup_guest(vmm);
	init_vm_exit_handlers(vmm);

	if (__vmxon(virt_to_phys(vmm->vmx_on))) {
		printf("VMXON failed\n");
		goto free_msr;
	}

	paddr_t vmcs_paddr = virt_to_phys(vmm->vmcs);
	if (__vmclear(vmcs_paddr)) {
		printf("VMCLEAR failed\n");
		goto free_vmxoff;
	}

	if (__vmptrld(vmcs_paddr)) {
		printf("VMPTRLD failed\n");
		goto free_vmxoff;
	}

	vmcs_write_vm_exec_controls(vmm);
	vmcs_write_vm_exit_controls(vmm);
	vmcs_write_vm_entry_controls(vmm);
	vmcs_write_vm_host_state(vmm);

#ifdef DEBUG
	dump_guest_state(&vmm->guest_state);
#endif

	vmcs_write_vm_guest_state(vmm);

	printf("Hello from VMX ROOT\n");
	printf("Entering guest ...\n");

	if (launch_vm(vmm)) {
		printf("VMLAUNCH failed\n");
		goto free_vmxoff;
	}

	return 0;

free_vmxoff:
	__vmxoff();
free_msr:
	kfree(vmm->msr_bitmap);
free_host:
	kfree((void *)(vmm->host_state.rsp - VM_EXIT_STACK_SIZE));
free_vmcs:
	release_vmcs(vmm->vmcs);
	return 1;
}
