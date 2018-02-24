#include <stdio.h>
#include <string.h>
#include <page.h>
#include <paging.h>
#include <x86.h>

#define KERNEL_START_PADDR 0x100000

extern char _end[];
extern u64 last_pfn;

/*
 * Setup kernel page tables, we're still on boot page tables.
 * The kernel will be located almost at the top of the virtual
 * address space. We need to temporary keep the kernel identity mapped,
 * switch to new mapping and then unmap our old flat mapping.
 */
int init_paging(void)
{
	/*
	 * 1MB has been kept unallocated at the top of valid physical
	 * located after the page_frame array.
	 * XXX: reuse boot_pgtable ? there is sufficent space.
	 */
	struct page_frame *last_frame = pfn_to_page(last_pfn);
	u64 addr = (u64)(last_frame + 1);

	pgd_t *new_pgd = (pgd_t *)__align_n(addr, PAGE_SIZE);
	pgd_t *boot_pgd = (pgd_t *)(read_cr3() & PAGE_MASK);

	memset(new_pgd, 0, PTRS_PER_TABLE * sizeof(pgd_t));

	/* Our new pgd still maps the first 4G in flat */
	new_pgd[0] = boot_pgd[0];

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
	addr = 0;

	/*
	 * PAGE_OFFSET vaddr maps paddr 0. Here, we only map the physical
	 * frames used by the kernel.
	 */
	for (off = pmd_offset(PAGE_OFFSET); off < PTRS_PER_TABLE; ++off) {
		pmd[off] = addr;
		if (addr >= KERNEL_START_PADDR && addr < (u64)_end)
			pmd[off] |= pg_common_flags|PG_HUGE_PAGE;

		for (u64 i = 0; i < (2 * BIG_PAGE_SIZE) / PAGE_SIZE; ++i) {
			struct page_frame *f = phys_to_page(addr);
			f->vaddr = phys_to_virt(addr);
			if (!list_empty(&f->free_list))
				list_remove(&f->free_list);
			addr += PAGE_SIZE;
		}

		if (addr > (u64)_end)
			break;
	}

	/*
	 * TODO we're still on the flat mapping, even after writing to cr3.
	 *      Before executing using the new mapping, DO NOT FORGET to map
	 *      the paging structure into the new kernel virtual addr space.
	 */

	write_cr3((paddr_t)new_pgd);

	return 0;
}
