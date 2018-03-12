#ifndef _GDT_H_
#define _GDT_H_

#define GDT_ENTRY_KERNEL_CS	1
#define GDT_ENTRY_KERNEL_DS	2
#define GDT_ENTRY_TSS		3

#define __KERNEL_CS		(GDT_ENTRY_KERNEL_CS*8)
#define __KERNEL_DS		(GDT_ENTRY_KERNEL_DS*8)
#define __TSS_ENTRY		(GDT_ENTRY_TSS*8)

#ifndef __ASM__
#include "types.h"
#include "compiler.h"
struct gdtr {
	u16 limit;
	u64 base;
} __packed;

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

void load_tss(void);

#endif /* __ASM__ */

#endif /* !_GDT_H_ */
