#include <stdio.h>
#include <string.h>
#include <page.h>
#include <paging.h>
#include <x86.h>

#define KERNEL_START_PADDR 0x100000

extern char _end[];
extern u64 last_pfn;

static inline void page_frame_used(struct page_frame *f)
{
	f->vaddr = phys_to_virt(page_to_phys(f));
	list_remove(&f->free_list);
}

/*
 * Setup kernel page tables, we're still on boot page tables.
 * The kernel will be located almost at the top of the virtual
 * address space. We need to temporary keep the kernel identity mapped,
 * switch to new mapping and then unmap our old flat mapping.
 */
int init_paging(void)
{
	pgd_t *boot_pgd = (pgd_t *)(read_cr3() & PAGE_MASK);
	pgd_t *new_pgd = boot_pgd;

	int pg_common_flags = PG_PRESENT|PG_WRITABLE|PG_GLOBAL;

	u64 off = pgd_offset(PAGE_OFFSET);
	new_pgd[off] = (pgd_t)new_pgd + PAGE_SIZE;
	new_pgd[off] |= pg_common_flags;

	pud_t *pud = new_pgd[off] & PAGE_MASK;
	off = pud_offset(PAGE_OFFSET);
	pud[off] = (pud_t)pud + PAGE_SIZE;
	pud[off] |= pg_common_flags;

	/* Each entry maps a 2MB page */
	pmd_t *pmd = pud[off] & PAGE_MASK;
	paddr_t addr = 0;

	/*
	 * PAGE_OFFSET vaddr maps paddr 0. Here, we map all the physical
	 * memory below _end. ATM, this is only one 2MB page.
	 */
	for (off = pmd_offset(PAGE_OFFSET); off < PTRS_PER_TABLE; ++off) {
		pmd[off] = addr;
		//TODO map kernel code as read only ...
		pmd[off] |= pg_common_flags|PG_HUGE_PAGE;

		addr += 2 * BIG_PAGE_SIZE;
		if (addr > (paddr_t)_end)
			break;
	}

	/* Removes kernel page frames from allocator pool */
	for (addr = KERNEL_START_PADDR; addr < (paddr_t)_end; addr += PAGE_SIZE)
		page_frame_used(phys_to_page(addr));

	//TODO (re)load IDTR with IDT virtual address

	write_cr3((paddr_t)new_pgd);

	return 0;
}
