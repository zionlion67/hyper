#include <cpuid.h>	/* compiler header */

#include <compiler.h>
#include <gdt.h>
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

#define _1GB	(1024 * 1024 * 1024)

/* Write back caching */
#define EPT_MEMORY_TYPE_WB	0x6

/* Build EPT structures. XXX: ATM, only 1GB RWX pages */
static int setup_ept_range(struct vmm *vmm, paddr_t host_start, paddr_t host_end,
			   paddr_t guest_start)
{
	/*
	 * vmx_on and vmcs are stored on a 2MB page ...
	 * There is 2MB - 8KB of space left for EPT structures.
	 */
	struct ept_pml4e *ept_pml4 = (vaddr_t)vmm->vmx_on + 2 * PAGE_SIZE;
	struct ept_huge_pdpte *ept_pdpt = (vaddr_t)ept_pml4 + PAGE_SIZE;

	u64 nb_1g_page = (host_end - host_start) / _1GB + 1;

	struct ept_pml4e *pml4e = ept_pml4 + pmd_offset(guest_start);
	pml4e->read = 1;
	pml4e->write = 1;
	pml4e->kern_exec = 1;
	pml4e->paddr = virt_to_phys(ept_pdpt) >> PAGE_SHIFT;

	struct ept_huge_pdpte *huge_pdpte = ept_pdpt + pud_offset(guest_start);
	for (u64 i = 0; i < EPT_PTRS_PER_TABLE && i < nb_1g_page; ++i) {
		huge_pdpte->read = 1;
		huge_pdpte->write = 1;
		huge_pdpte->kern_exec = 1;
		huge_pdpte->memory_type = EPT_MEMORY_TYPE_WB;
		huge_pdpte->ignore_pat = 1;
		huge_pdpte->huge_page = 1;
		huge_pdpte->paddr = host_start + i * _1GB;
	}

	return 0;
}

/* XXX: ATM allocates 200M of memory for the VM */
static int setup_ept(struct vmm *vmm)
{
	u8 nb_pages = 10;
	void *p = alloc_pages(nb_pages);
	if (p == NULL)
		return 1;

	paddr_t start = virt_to_phys(p);
	paddr_t end = start + nb_pages * ALLOC_PAGE_SIZE;
	return setup_ept_range(vmm, start, end, 0);
}

struct segment_selectors {
	u16	cs;
	u16	ds;
	u16	es;
	u16	ss;
	u16	fs;
	u16	gs;
};

/* Loaded during VM-exits */
struct vmcs_host_state {
	u64	cr0;
	u64	cr3;
	u64	cr4;

	struct segment_selectors selectors;

	u64	tr_base;
	u64	gdtr_base;
	u64	idtr_base;

	u32	ia32_sysenter_cs;
	u64	ia32_fs_base;
	u64	ia32_gs_base;
	u64	ia32_sysenter_esp;
	u64	ia32_sysenter_eip;
	u64	ia32_perf_global_ctrl;
	u64	ia32_pat;
	u64	ia32_efer;

	u64	rsp;
	u64	rip;
};

static void vmcs_get_host_selectors(struct segment_selectors *sel)
{
	sel->cs = read_cs();
	sel->ds = read_ds();
	sel->es = read_es();
	sel->ss = read_ss();
	sel->fs = read_fs();
	sel->gs = read_gs();
}

#define JUNK_ADDR 0xdeadbeef
static void vmcs_get_host_state(struct vmcs_host_state *state)
{
	state->cr0 = read_cr0();
	state->cr3 = read_cr3();
	state->cr4 = read_cr4();

	vmcs_get_host_selectors(&state->selectors);

	struct gdtr gdtr;
	__sgdt(&gdtr);
	state->gdtr_base = gdtr.base;

	__sidt(&gdtr); /* gdtr has the same memory layout */
	state->idtr_base = gdtr.base;

	state->tr_base = (u64)tss;

	state->ia32_fs_base = __readmsr(MSR_FS_BASE);
	state->ia32_gs_base = __readmsr(MSR_GS_BASE);
	state->ia32_sysenter_cs = __readmsr(MSR_SYSENTER_CS);
	state->ia32_sysenter_esp = __readmsr(MSR_SYSENTER_ESP);
	state->ia32_sysenter_eip = __readmsr(MSR_SYSENTER_EIP);
	state->ia32_perf_global_ctrl = __readmsr(MSR_PERF_GLOBAL_CTRL);
	state->ia32_pat = __readmsr(MSR_PAT);
	state->ia32_efer = __readmsr(MSR_EFER);

	state->rsp = JUNK_ADDR;
	state->rip = JUNK_ADDR;
}

int vmcs_setup_host_state(struct vmm *vmm)
{
	struct vmcs_host_state state;
	vmcs_get_host_state(&state);
	(void)vmm;
	return 0;
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
	vmcs_write_control(vmm, PIN_BASED_VM_EXEC_CONTROL, ctl, MSR_VMX_PIN_CTLS);
}

static inline void vmcs_write_proc_based_ctrls(struct vmm *vmm, u64 ctl)
{
	vmcs_write_control(vmm, CPU_BASED_VM_EXEC_CONTROL, ctl, MSR_VMX_PROC_CTLS);
}

static inline void vmcs_write_proc_based_ctrls2(struct vmm *vmm, u64 ctl)
{

	vmcs_write_control(vmm, SECONDARY_VM_EXEC_CONTROL, ctl, MSR_VMX_PROC_CTLS2);
}

static void vmcs_write_vm_exec_controls(struct vmm *vmm)
{
	vmcs_write_pin_based_ctrls(vmm, 0);
	vmcs_write_proc_based_ctrls(vmm, ENABLE_SECONDARY_EXEC_CTLS);
	vmcs_write_proc_based_ctrls2(vmm, ENABLE_EPT|UNRESTRICTED_GUEST);

	__vmwrite(EXCEPTION_BITMAP, 0);
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
	write_cr0(cr0);

	u64 cr4 = read_cr4();
	cr4 |= CR4_VMXE;
	cr4 |= vmm->vmx_msr[VMM_MSR_VMX_CR4_FIXED0];
	write_cr4(cr4);

	vmcs_setup_host_state(vmm);

	if (setup_ept(vmm)) {
		printf("Failed to setup EPT\n");
		goto free_vmcs;
	}

	if (__vmx_on(virt_to_phys(vmm->vmx_on))) {
		printf("VMXON failed\n");
		goto free_vmcs;
	}

	paddr_t vmcs_paddr = virt_to_phys(vmm->vmcs);
	if (__vmclear(vmcs_paddr)) {
		printf("VMCLEAR failed\n");
		goto free_vmcs;
	}

	if (__vmptrld(vmcs_paddr)) {
		printf("VMPTRLD failed\n");
		goto free_vmcs;
	}

	vmcs_write_vm_exec_controls(vmm);

	printf("Hello from VMX ROOT\n");

	return 0;

free_vmcs:
	release_vmcs(vmm->vmcs);
	return 1;
}
