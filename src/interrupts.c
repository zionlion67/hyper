#include <interrupts.h>
#include <gdt.h>
#include <stdio.h>
#include <x86.h>

irqhandler_t interrupt_handlers[NR_INTERRUPTS];

static struct idt_gate idt[NR_INTERRUPTS];

struct idtr {
	u16 limit;
	u64 base;
} __packed;

struct exception_str {
	const char *name;
	const char *abbr;
};

#define EX_STR(Name, Abbr) \
	{ .name = Name, .abbr = Abbr }

static struct exception_str exceptions_str[] = {
	EX_STR("Divide Error", 		"DE"),
	EX_STR("Debug Exception", 	"DB"),
	EX_STR("NMI Interrupt", 	"XX"),
	EX_STR("Breakpoint", 		"BP"),
	EX_STR("Overflow", 		"OF"),
	EX_STR("BOUND Range Exceeded", 	"BR"),
	EX_STR("Invalid Opcode", 	"UD"),
	EX_STR("Device Not Available", 	"NM"),
	EX_STR("Double Fault", 		"DF"),
	EX_STR("Coprocessor Segment",	"XX"),
	EX_STR("Invalid TSS",		"TS"),
	EX_STR("Segment Not Present",	"NP"),
	EX_STR("Stack fault",		"SS"),
	EX_STR("General Protection",	"GP"),
	EX_STR("Page Fault",		"PF"),
	EX_STR("x87 FPU Error",		"MF"),
	EX_STR("Alignment Check",	"AC"),
	EX_STR("Machine-Check",		"MC"),
	EX_STR("SIMD Floating-Point",	"XM"),
	EX_STR("Virtualization",	"VE"),
};

static int add_gate(const u16 irq, u64 handler, u8 ist, u8 flags)
{
	if (irq >= NR_INTERRUPTS)
		return -1;

	struct idt_gate *gate = &idt[irq];

	gate->offset_lo = handler & 0xffff;
	gate->offset_mi = (handler & 0xffff0000) >> 16;
	gate->offset_hi = handler >> 32;

	if (flags & IDT_KERNEL_GATE) {
		gate->selector = __KERNEL_CS;
		gate->dpl = 0;
	}

	gate->ist = ist;

	if (flags & IDT_TRAP_GATE)
		gate->type = IDT_TRAP_GATE_TYPE;
	else if (flags & IDT_INTR_GATE)
		gate->type = IDT_INTR_GATE_TYPE;
	else
		return -1;

	gate->p = 1;
	return 0;

}

static void dump_context(const struct irq_frame *f)
{
#define X(reg) \
	printf(#reg": 0x%x%x\n", f->reg >> 32, f->reg & 0xffffffff);
	X(rax);
	X(rbx);
	X(rcx);
	X(rdx);
	X(rsi);
	X(rdi);
	X(rsp);
	X(rbp);
	X(rip);
	X(rflags);
	X(error_code);
#undef X
	printf("CR2: ");
	print64(read_cr2());
	printf("\n");
}

static void default_irq_handler(struct irq_frame *frame)
{
	if (frame->irq < 20)
		printf("Interrupt: %s Exception\n", exceptions_str[frame->irq]);
	dump_context(frame);
	printf("Halting ...\n");
	for (;;)
		asm volatile ("hlt");
}

extern void isr_stub_0(void);
int init_idt(void)
{
	u64 start = (u64)isr_stub_0;
	for (u16 i = 0; i < NR_INTERRUPTS; ++i) {
		interrupt_handlers[i] = default_irq_handler;
		add_gate(i, start + i * 16, 0, IDT_KERNEL_GATE|IDT_INTR_GATE);
	}

	struct idtr idtr = {
		.limit = sizeof(idt) - 1,
		.base = (u64)idt,
	};

	asm volatile ("lidt %0" : /* No outputs */ : "m"(idtr) : "memory");
	return 0;
}
