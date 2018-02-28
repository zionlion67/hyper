#ifndef _PAGE_H_
#define _PAGE_H_

#include "page_types.h"
#include <list.h>
#include <multiboot2.h>
#include <x86.h>

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

// TODO static inline these
paddr_t page_to_phys(struct page_frame *frame);
struct page_frame *phys_to_page(paddr_t addr);
struct page_frame *pfn_to_page(u64 pfn);
int memory_init(struct multiboot_tag_mmap *mmap);

struct page_frame *alloc_page_frames(vaddr_t vaddr, u64 n);
void release_page_frames(struct page_frame *p, u64 n);

static inline paddr_t virt_to_phys(vaddr_t vaddr)
{
	return vaddr - PAGE_OFFSET;
}

static inline vaddr_t phys_to_virt(paddr_t paddr)
{
	return paddr + PAGE_OFFSET;
}

static inline pgd_t *kernel_pgd(void)
{
	return (pgd_t *)phys_to_virt(read_cr3() & PAGE_MASK);
}

static inline pud_t *kernel_pud(void)
{
	const pgd_t *pgd = kernel_pgd();
	const u64 off = pgd_offset(PAGE_OFFSET);
	return (pud_t *)phys_to_virt(pgd[off] & PAGE_MASK);
}

static inline pmd_t *kernel_pmd(void)
{
	const pud_t *pud = kernel_pud();
	const u64 off = pud_offset(PAGE_OFFSET);
	return (pmd_t *)phys_to_virt(pud[off] & PAGE_MASK);
}

static inline void map_frames(pmd_t *pmd, struct page_frame *f, u64 n, u32 flags)
{
	for (u64 i = 0; i < n; ++i, f += FRAMES_PER_2M_PAGE) {
		pmd[i] = page_to_phys(f);
		pmd[i] |= flags;
	}
}

static inline void map_frame(pmd_t *pmd, struct page_frame *f, u32 flags)
{
	map_frames(pmd, f, 1, flags);
}

static inline struct page_frame *alloc_page_frame(vaddr_t vaddr)
{
	return alloc_page_frames(vaddr, 1);
}

static inline void release_page_frame(struct page_frame *f)
{
	release_page_frames(f, 1);
}

#endif /* !_PAGE_H_ */
