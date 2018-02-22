#ifndef _PAGE_H_
#define _PAGE_H_

#include "page_types.h"
#include <list.h>
#include <multiboot2.h>

#define MEM_RAM_USABLE	(1 << 0)
#define MEM_RESERVED	(1 << 2)
#define MEM_LOW_MEM	(1 << 3)

struct mem_zone {
	u64 start;
	u64 length;
	u8  type;
};

struct page_frame {
	vaddr_t vaddr;
	struct list free_list;
};

int memory_init(struct multiboot_tag_mmap *mmap);

#endif /* !_PAGE_H_ */
