#ifndef _VMX_H_
#define _VMX_H_

#include "x86.h"
#include "ept.h"
#include "vmx_guest.h"
#include <stdio.h>

#define NR_VMX_MSR 17

/* VM Execution control fields */
#define VM_EXEC_CR3_LOAD_EXIT			(1 << 15)
#define VM_EXEC_USE_MSR_BITMAPS			(1 << 28)
#define VM_EXEC_ENABLE_PROC_CTLS2		(1 << 31)
#define VM_EXEC_ENABLE_EPT			(1 << 1)
#define VM_EXEC_UNRESTRICTED_GUEST		(1 << 7)

/* VM Exit control fields */
#define VM_EXIT_SAVE_DBG_CTLS			(1 << 2)
#define VM_EXIT_LONG_MODE			(1 << 9)
#define VM_EXIT_LOAD_MSR_PERF_GLOBAL		(1 << 12)
#define VM_EXIT_ACK_INTR_ON_EXIT		(1 << 15)
#define VM_EXIT_SAVE_MSR_PAT			(1 << 18)
#define VM_EXIT_LOAD_MSR_PAT			(1 << 19)
#define VM_EXIT_SAVE_MSR_EFER			(1 << 20)
#define VM_EXIT_LOAD_MSR_EFER			(1 << 21)
#define VM_EXIT_SAVE_VMX_TIMER			(1 << 22)
#define VM_EXIT_CLEAR_MSR_BNDCFGS		(1 << 23)
#define VM_EXIT_CONCEAL_INTEL_PT		(1 << 24)

/* VM Entry control fields */
#define VM_ENTRY_LOAD_DBG_CTLS			(1 << 2)
#define VM_ENTRY_IA32E_GUEST			(1 << 9)
#define VM_ENTRY_SMM_ENTRY			(1 << 10)
#define VM_ENTRY_DISABLE_DUAL_MONITOR		(1 << 11)
#define VM_ENTRY_LOAD_MSR_PERF_GLOBAL		(1 << 13)
#define VM_ENTRY_LOAD_MSR_PAT			(1 << 14)
#define VM_ENTRY_LOAD_MSR_EFER			(1 << 15)
#define VM_ENTRY_LOAD_MSR_BNDCFGS		(1 << 16)
#define VM_ENTRY_CONCEAL_INTEL_PT		(1 << 17)

/* Enum is copy-pasted from SimpleVisor */
enum vmcs_field {
    VIRTUAL_PROCESSOR_ID            = 0x00000000,
    POSTED_INTR_NOTIFICATION_VECTOR = 0x00000002,
    EPTP_INDEX                      = 0x00000004,
    GUEST_ES_SELECTOR               = 0x00000800,
    GUEST_CS_SELECTOR               = 0x00000802,
    GUEST_SS_SELECTOR               = 0x00000804,
    GUEST_DS_SELECTOR               = 0x00000806,
    GUEST_FS_SELECTOR               = 0x00000808,
    GUEST_GS_SELECTOR               = 0x0000080a,
    GUEST_LDTR_SELECTOR             = 0x0000080c,
    GUEST_TR_SELECTOR               = 0x0000080e,
    GUEST_INTR_STATUS               = 0x00000810,
    GUEST_PML_INDEX                 = 0x00000812,
    HOST_ES_SELECTOR                = 0x00000c00,
    HOST_CS_SELECTOR                = 0x00000c02,
    HOST_SS_SELECTOR                = 0x00000c04,
    HOST_DS_SELECTOR                = 0x00000c06,
    HOST_FS_SELECTOR                = 0x00000c08,
    HOST_GS_SELECTOR                = 0x00000c0a,
    HOST_TR_SELECTOR                = 0x00000c0c,
    IO_BITMAP_A                     = 0x00002000,
    IO_BITMAP_B                     = 0x00002002,
    MSR_BITMAP                      = 0x00002004,
    VM_EXIT_MSR_STORE_ADDR          = 0x00002006,
    VM_EXIT_MSR_LOAD_ADDR           = 0x00002008,
    VM_ENTRY_MSR_LOAD_ADDR          = 0x0000200a,
    PML_ADDRESS                     = 0x0000200e,
    TSC_OFFSET                      = 0x00002010,
    VIRTUAL_APIC_PAGE_ADDR          = 0x00002012,
    APIC_ACCESS_ADDR                = 0x00002014,
    PI_DESC_ADDR                    = 0x00002016,
    VM_FUNCTION_CONTROL             = 0x00002018,
    EPT_POINTER                     = 0x0000201a,
    EOI_EXIT_BITMAP0                = 0x0000201c,
    EPTP_LIST_ADDR                  = 0x00002024,
    VMREAD_BITMAP                   = 0x00002026,
    VMWRITE_BITMAP                  = 0x00002028,
    VIRT_EXCEPTION_INFO             = 0x0000202a,
    XSS_EXIT_BITMAP                 = 0x0000202c,
    TSC_MULTIPLIER                  = 0x00002032,
    GUEST_PHYSICAL_ADDRESS          = 0x00002400,
    VMCS_LINK_POINTER               = 0x00002800,
    GUEST_DEBUGCTL                  = 0x00002802,
    GUEST_PAT                       = 0x00002804,
    GUEST_EFER                      = 0x00002806,
    GUEST_PERF_GLOBAL_CTRL          = 0x00002808,
    GUEST_PDPTE0                    = 0x0000280a,
    GUEST_BNDCFGS                   = 0x00002812,
    HOST_PAT                        = 0x00002c00,
    HOST_EFER                       = 0x00002c02,
    HOST_PERF_GLOBAL_CTRL           = 0x00002c04,
    PIN_BASED_VM_EXEC_CONTROL       = 0x00004000,
    CPU_BASED_VM_EXEC_CONTROL       = 0x00004002,
    EXCEPTION_BITMAP                = 0x00004004,
    PAGE_FAULT_ERROR_CODE_MASK      = 0x00004006,
    PAGE_FAULT_ERROR_CODE_MATCH     = 0x00004008,
    CR3_TARGET_COUNT                = 0x0000400a,
    VM_EXIT_CONTROLS                = 0x0000400c,
    VM_EXIT_MSR_STORE_COUNT         = 0x0000400e,
    VM_EXIT_MSR_LOAD_COUNT          = 0x00004010,
    VM_ENTRY_CONTROLS               = 0x00004012,
    VM_ENTRY_MSR_LOAD_COUNT         = 0x00004014,
    VM_ENTRY_INTR_INFO              = 0x00004016,
    VM_ENTRY_EXCEPTION_ERROR_CODE   = 0x00004018,
    VM_ENTRY_INSTRUCTION_LEN        = 0x0000401a,
    TPR_THRESHOLD                   = 0x0000401c,
    SECONDARY_VM_EXEC_CONTROL       = 0x0000401e,
    PLE_GAP                         = 0x00004020,
    PLE_WINDOW                      = 0x00004022,
    VM_INSTRUCTION_ERROR            = 0x00004400,
    VM_EXIT_REASON                  = 0x00004402,
    VM_EXIT_INTR_INFO               = 0x00004404,
    VM_EXIT_INTR_ERROR_CODE         = 0x00004406,
    IDT_VECTORING_INFO              = 0x00004408,
    IDT_VECTORING_ERROR_CODE        = 0x0000440a,
    VM_EXIT_INSTRUCTION_LEN         = 0x0000440c,
    VMX_INSTRUCTION_INFO            = 0x0000440e,
    GUEST_ES_LIMIT                  = 0x00004800,
    GUEST_CS_LIMIT                  = 0x00004802,
    GUEST_SS_LIMIT                  = 0x00004804,
    GUEST_DS_LIMIT                  = 0x00004806,
    GUEST_FS_LIMIT                  = 0x00004808,
    GUEST_GS_LIMIT                  = 0x0000480a,
    GUEST_LDTR_LIMIT                = 0x0000480c,
    GUEST_TR_LIMIT                  = 0x0000480e,
    GUEST_GDTR_LIMIT                = 0x00004810,
    GUEST_IDTR_LIMIT                = 0x00004812,
    GUEST_ES_AR_BYTES               = 0x00004814,
    GUEST_CS_AR_BYTES               = 0x00004816,
    GUEST_SS_AR_BYTES               = 0x00004818,
    GUEST_DS_AR_BYTES               = 0x0000481a,
    GUEST_FS_AR_BYTES               = 0x0000481c,
    GUEST_GS_AR_BYTES               = 0x0000481e,
    GUEST_LDTR_AR_BYTES             = 0x00004820,
    GUEST_TR_AR_BYTES               = 0x00004822,
    GUEST_INTERRUPTIBILITY_INFO     = 0x00004824,
    GUEST_ACTIVITY_STATE            = 0x00004826,
    GUEST_SMBASE                    = 0x00004828,
    GUEST_SYSENTER_CS               = 0x0000482a,
    GUEST_PREEMPTION_TIMER          = 0x0000482e,
    HOST_SYSENTER_CS                = 0x00004c00,
    CR0_GUEST_HOST_MASK             = 0x00006000,
    CR4_GUEST_HOST_MASK             = 0x00006002,
    CR0_READ_SHADOW                 = 0x00006004,
    CR4_READ_SHADOW                 = 0x00006006,
    CR3_TARGET_VALUE0               = 0x00006008,
    EXIT_QUALIFICATION              = 0x00006400,
    GUEST_LINEAR_ADDRESS            = 0x0000640a,
    GUEST_CR0                       = 0x00006800,
    GUEST_CR3                       = 0x00006802,
    GUEST_CR4                       = 0x00006804,
    GUEST_ES_BASE                   = 0x00006806,
    GUEST_CS_BASE                   = 0x00006808,
    GUEST_SS_BASE                   = 0x0000680a,
    GUEST_DS_BASE                   = 0x0000680c,
    GUEST_FS_BASE                   = 0x0000680e,
    GUEST_GS_BASE                   = 0x00006810,
    GUEST_LDTR_BASE                 = 0x00006812,
    GUEST_TR_BASE                   = 0x00006814,
    GUEST_GDTR_BASE                 = 0x00006816,
    GUEST_IDTR_BASE                 = 0x00006818,
    GUEST_DR7                       = 0x0000681a,
    GUEST_RSP                       = 0x0000681c,
    GUEST_RIP                       = 0x0000681e,
    GUEST_RFLAGS                    = 0x00006820,
    GUEST_PENDING_DBG_EXCEPTIONS    = 0x00006822,
    GUEST_SYSENTER_ESP              = 0x00006824,
    GUEST_SYSENTER_EIP              = 0x00006826,
    HOST_CR0                        = 0x00006c00,
    HOST_CR3                        = 0x00006c02,
    HOST_CR4                        = 0x00006c04,
    HOST_FS_BASE                    = 0x00006c06,
    HOST_GS_BASE                    = 0x00006c08,
    HOST_TR_BASE                    = 0x00006c0a,
    HOST_GDTR_BASE                  = 0x00006c0c,
    HOST_IDTR_BASE                  = 0x00006c0e,
    HOST_SYSENTER_ESP               = 0x00006c10,
    HOST_SYSENTER_EIP               = 0x00006c12,
    HOST_RSP                        = 0x00006c14,
    HOST_RIP                        = 0x00006c16,
};

struct segment_selectors {
	u16	cs;
	u16	ds;
	u16	es;
	u16	ss;
	u16	fs;
	u16	gs;
	u16	tr;
};

struct control_regs {
	u64	cr0;
	u64	cr3;
	u64	cr4;
};

struct vmcs_state_msr {
	u32	ia32_sysenter_cs;
	u64	ia32_fs_base;
	u64	ia32_gs_base;
	u64	ia32_sysenter_esp;
	u64	ia32_sysenter_eip;
	u64	ia32_perf_global_ctrl;
	u64	ia32_pat;
	u64	ia32_efer;
	u64	ia32_debugctl;
	u64	ia32_bndcfgs;
};

/* Loaded during VM-exits */
struct vmcs_host_state {
	struct control_regs control_regs;
	struct segment_selectors selectors;

	u64	tr_base;
	u64	gdtr_base;
	u64	idtr_base;

	struct vmcs_state_msr msr;

	u64	rsp;
	u64	rip;
};

struct segment_descriptor {
	u16	selector;
	u64	base;
	u32	limit;
	union {
		struct {
			u32	type : 4;
			u32	s : 1;
			u32	dpl : 2;
			u32	p : 1;
			u32	reserved1 : 4;
			u32	avl : 1;
			u32	l : 1;
			u32	db : 1;
			u32	g : 1;
			u32	unusable : 1;
			u32	reserved2 : 15;
		};
		u32	access;
	};
	/* GUEST_*_SELECTOR */
	enum vmcs_field	base_field;
} __packed;

struct segment_descriptors {
	struct segment_descriptor cs;
	struct segment_descriptor ds;
	struct segment_descriptor es;
	struct segment_descriptor ss;
	struct segment_descriptor fs;
	struct segment_descriptor gs;
	struct segment_descriptor tr;
	struct segment_descriptor ldtr;
};

struct table_register {
	u32	limit;
	u64	base;
};

struct vmcs_guest_register_state {
	struct control_regs control_regs;

	struct segment_descriptors seg_descs;

	struct table_register gdtr;
	struct table_register idtr;

	struct vmcs_state_msr msr;

	struct x86_regs regs;
	u64	dr7;
};

struct vmcs_guest_state {
	struct vmcs_guest_register_state reg_state;

	u32	intr_state; /* interuptability */
	u32	activity_state;
	u32	preempt_timer;
	u16	intr_status;
	u16	pml_index;
	u64	vmcs_link;
	u64	pdpte[4];
};

struct vaddr_range {
	vaddr_t start;
	vaddr_t end;
};

struct vmcs;
struct vmm {
	u64 vmx_msr[NR_VMX_MSR];

	struct vmcs *vmx_on;
	struct vmcs *vmcs;

	struct vaddr_range guest_mem;
	struct vaddr_range guest_img;

	struct eptp eptp;
	struct vmcs_host_state host_state;
	struct vmcs_guest_state guest_state;

	u8 *msr_bitmap;

	int (*setup_guest)(struct vmm *);
};

int has_vmx_support(void);
int vmm_init(struct vmm *);
void dump_guest_state(struct vmcs_guest_state *state);
const char *get_vmcs_field_str(enum vmcs_field field);
int init_vm_exit_handlers(struct vmm *vmm);

/*
 * Assembly magic to execute VMX instructions that
 * only take a physical address as operand.
 */
#define __vmx_insn_paddr(insn, paddr)		\
({						\
	int __ret;				\
	asm volatile (#insn" %[addr]\n\t"	\
		      "jbe 1f\n\t"		\
		      "mov $0, %[ret]\n\t"	\
		      "jmp 2f\n\t"		\
		      "1:\n\t"			\
		      "mov $1, %[ret]\n\t"	\
		      "2:"			\
		     : [ret] "=r"(__ret)	\
		     : [addr] "m"(paddr)	\
		     : "cc"			\
		    );				\
	__ret;					\
})

static inline int __vmxon(paddr_t paddr)
{
	return __vmx_insn_paddr(vmxon, paddr);
}

static inline int __vmclear(paddr_t paddr)
{
	return __vmx_insn_paddr(vmclear, paddr);
}

static inline int __vmptrld(paddr_t paddr)
{
	return __vmx_insn_paddr(vmptrld, paddr);
}

static inline void __vmxoff(void)
{
	asm volatile ("vmxoff");
}

static inline u8 __vmread(enum vmcs_field field, void *val)
{
	u8 err = 0;
	asm volatile ("vmread %[field], %[val]\n\t"
		      "setna %[error]\n\t"
		      : [error] "=r"(err)
		      : [field] "r"((u64)field), [val] "m"(*(u64 *)val)
		      : "memory"
		     );
	return err;
}

static inline const char *vmcs_field_str(enum vmcs_field field)
{
	return get_vmcs_field_str(field);
}

static inline void __vmwrite(enum vmcs_field field, u64 value)
{
#ifdef DEBUG
	const char *str = vmcs_field_str(field);
	if (str)
		printf("VMWRITE: %s = 0x%lx\n", str, value);
	else
		printf("VMWRITE: 0x%x = 0x%lx\n", field, value);
#endif
	asm volatile goto ("vmwrite %1, %0\n\t"
		      	   "jbe %l2\n\t"
		      	   :
			   : "r"((u64)field), "r"(value)
			   : "memory"
			   : fail
			  );
	return;
fail:
	printf("VMWRITE failed: field=0x%x\tval=0x%lx\n", field, value);
}

static inline int __vmlaunch(void)
{
	asm volatile goto("vmlaunch\n\t"
			  "jbe %l0"
			  :
			  :
			  :
			  : fail);
	return 0;
fail:
	return 1;
}

static inline u64 adjust_vm_control(u64 value, u64 ctrl_msr)
{
	value |= ctrl_msr & 0xffffffff; /* Required 1-settings */
	value &= ctrl_msr >> 32;	/* Required 0-settings */
	return value;
}

#endif /* !_VMX_H_ */
