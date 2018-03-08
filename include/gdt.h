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
struct gdtr {
	u16 limit;
	u64 base;
} __packed;

#endif /* __ASM__ */

#endif /* !_GDT_H_ */
