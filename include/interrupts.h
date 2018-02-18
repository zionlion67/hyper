#ifndef _INTERRUPTS_H_
#define _INTERRUPTS_H_

#include <types.h>
#include <compiler.h>

#define NR_INTERRUPTS 256

#define IDT_KERNEL_GATE	(1 << 0)
#define IDT_INTR_GATE	(1 << 1)
#define IDT_TRAP_GATE	(1 << 2)

#define IDT_INTR_GATE_TYPE 14
#define IDT_TRAP_GATE_TYPE 15


struct irq_frame {
	u64	irq;
	u16	gs;
	u16	fs;
	u64	rsi;
	u64	rdi;
	u64	rdx;
	u64	rcx;
	u64	rbx;
	u64	rax;
	u64	error_code;
	u64	rip;
	u64	cs;
	u64	rflags;
	u64	rsp;
	u64	ss;
} __packed;

struct idt_gate {
	union {
		u64	gate;
		struct	{
			u16	offset_lo;	
			u16	selector;
			u8	ist : 3;
			u8	zero : 5;
			u8	type : 4;
			u8	zero1 : 1;
			u8	dpl : 2;
			u8	p : 1;
			u16	offset_mi;
		} __packed;
	};

	u32	offset_hi;
	u32	reserved;
} __packed;

typedef void (*irqhandler_t)(struct irq_frame *);

int init_idt(void);

#endif
