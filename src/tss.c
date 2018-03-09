#include <string.h>
#include <page.h>
#include <x86.h>

struct gdt_desc {
	union {
		struct {
			u16	limit_lo;
			u16	base_lo;
			u8	base_mi;
			u8	type : 4;
			u8	s : 1;
			u8	dpl : 2;
			u8	p : 1;
			u8	limit_hi : 4;
			u8	avl : 1;
			u8	l : 1;
			u8	db : 1;
			u8	g : 1;
			u8	base_hi;
		};
		u64	quad;
	};
} __packed;

struct tss {
	u32	reserved0;
	u64	rsp0;
	u64	rsp1;
	u64	rsp2;
	u64	reserved1;
	u64	ist1;
	u64	ist2;
	u64	ist3;
	u64	ist4;
	u64	ist5;
	u64	ist6;
	u64	ist7;
	u64	reserved2;
	u16	reserved3;
	u16	io_bitmap_addr;
} __packed;

struct tss_descriptor {
	struct gdt_desc tss_lo;
	struct gdt_desc tss_hi;
};

/* Used in VMCS host state setup */
struct tss tss;

static inline struct gdt_desc *get_gdt_ptr(void)
{
	struct gdtr gdtr;
	__sgdt(&gdtr);

	return (struct gdt_desc *)gdtr.base;
}

/* TODO add descriptor manipulation functions ... */
#define GDT_TSS_DESC_TYPE 0x9 /* defined by Intel */
void load_tss(void)
{
	u32 limit = sizeof(struct tss);
	u64 tss_addr = virt_to_phys((u64)&tss);

	struct gdt_desc *gdt = get_gdt_ptr();
	struct tss_descriptor *tss_descriptor = (void *)&gdt[GDT_ENTRY_TSS];
	memset(tss_descriptor, 0, sizeof(struct tss_descriptor));
	struct gdt_desc *tss_desc = &tss_descriptor->tss_lo;

	tss_desc->limit_lo = limit & 0xffff;
	tss_desc->base_lo = tss_addr & 0xffff;
	tss_desc->base_mi = (tss_addr >> 16) & 0xff;
	tss_desc->type = GDT_TSS_DESC_TYPE;
	tss_desc->p = 1;
	tss_desc->limit_hi = (limit >> 16) & 0xf;
	tss_desc->base_hi = (tss_addr >> 24) & 0xf;

	tss_descriptor->tss_hi.quad = tss_addr >> 32;
	asm volatile ("ltrw %w0" : : "r"(__TSS_ENTRY));
}
