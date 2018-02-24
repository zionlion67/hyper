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

paddr_t page_to_phys(struct page_frame *frame);
struct page_frame *phys_to_page(paddr_t addr);
struct page_frame *pfn_to_page(u64 pfn);
int memory_init(struct multiboot_tag_mmap *mmap);

static inline paddr_t virt_to_phys(vaddr_t vaddr)
{
	return vaddr - PAGE_OFFSET;
}

#endif /* !_PAGE_H_ */
