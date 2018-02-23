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

	//TODO page frames corresponding to kernel are still
	//     considered available by the frame allocator ...
	//     Either map them here directly or handle this in the frame
	//     allocator initialization ...

	memset(new_pgd, 0, PTRS_PER_TABLE * sizeof(pgd_t));

	/* Our new pgd still maps the first 4G in flat */
	new_pgd[0] = boot_pgd[0];

	u64 off = pgd_offset(PAGE_OFFSET);
	new_pgd[off] = (pgd_t)new_pgd + PAGE_SIZE;
	new_pgd[off] |= PG_PRESENT|PG_WRITABLE|PG_GLOBAL;

	pud_t *pud = new_pgd[off] & PAGE_MASK;
	off = pud_offset(PAGE_OFFSET);
	pud[off] = (pud_t)pud + PAGE_SIZE;
	pud[off] |= PG_PRESENT|PG_WRITABLE|PG_GLOBAL;

	/* Each entry maps a 2MB page */
	pmd_t *pmd = pud[off] & PAGE_MASK;
	addr = KERNEL_START_PADDR;
	for (u64 i = 0, off = pmd_offset(PAGE_OFFSET); i < PTRS_PER_TABLE; ++i, ++off) {
		pmd[off] = addr;
		pmd[off] |= PG_PRESENT|PG_WRITABLE|PG_GLOBAL|PG_HUGE_PAGE;
		addr += 2 * BIG_PAGE_SIZE;
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
