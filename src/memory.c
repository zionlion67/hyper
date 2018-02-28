#include <page.h>
#include <x86.h>

/*
 * Allocates pages in kernel space.
 *
 * XXX: ATM only 2MB pages are handled
 * TODO: add read-only and NX
 */
void *alloc_pages(u64 n)
{
	u64 off;
	pmd_t *pmd = kernel_pmd();

	for (off = 0; off <= PTRS_PER_TABLE - n; ++off) {
		if (pg_present(pmd[off]))
			continue;
		u64 i;
		for (i = 1; i < n && off + i < PTRS_PER_TABLE; ++i)
			if (pg_present(pmd[off + i]))
				break;
		if (i != n)
			off = i + 1;
		else
			break;
	}
	if (off > PTRS_PER_TABLE - n)
		return NULL;

	struct page_frame *f = alloc_page_frames(pmd + off, n * FRAMES_PER_2M_PAGE);
	if (f == NULL)
		return NULL;

	map_frames(pmd + off, f, n, PG_PRESENT|PG_WRITABLE|PG_HUGE_PAGE);
	return (void *)phys_to_virt(page_to_phys(f));
}

void release_pages(void *p, u64 n)
{
	pmd_t *pmd = kernel_pmd();
	u64 off = pmd_offset((vaddr_t)p);

	for (u64 i = 0; i < n ; ++i, ++off) {
		pmd_t *entry = &pmd[off];
		struct page_frame *f = phys_to_page(*entry & PAGE_MASK);
		release_page_frames(f, FRAMES_PER_2M_PAGE);
		*entry &= ~PG_PRESENT;
	}
}
